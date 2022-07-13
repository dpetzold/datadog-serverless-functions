# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2021 Datadog, Inc.

import json
import boto3
import re
import logging

from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.metric import lambda_stats

from .trace_forwarder.connection import TraceConnection
from .enhanced_lambda_metrics import (
    get_enriched_lambda_log_tags,
    parse_and_submit_enhanced_metrics,
)
from .logs import forward_logs
from .parsing import (
    parse_event,
    separate_security_hub_findings,
    parse_aws_waf_logs,
)
from .telemetry import (
    DD_FORWARDER_TELEMETRY_NAMESPACE_PREFIX,
    get_forwarder_telemetry_tags,
)
from .settings import (
    DD_ADDITIONAL_TARGET_LAMBDAS,
    DD_API_KEY,
    DD_CUSTOM_TAGS,
    DD_FORWARDER_VERSION,
    DD_FORWARD_LOG,
    DD_HOST,
    DD_LOG_LEVEL,
    DD_SERVICE,
    DD_SKIP_SSL_VALIDATION,
    DD_SOURCE,
    DD_TRACE_INTAKE_URL,
    config_logging,
    validate_api_key,
)

logger = logging.getLogger()


trace_connection = TraceConnection(
    DD_TRACE_INTAKE_URL, DD_API_KEY, DD_SKIP_SSL_VALIDATION
)

HOST_IDENTITY_REGEXP = re.compile(
    r"^arn:aws:sts::.*?:assumed-role\/(?P<role>.*?)/(?P<host>i-([0-9a-f]{8}|[0-9a-f]{17}))$"
)


config_logging(DD_LOG_LEVEL)

validate_api_key()


def datadog_forwarder(event, context):

    """The actual lambda function entry point"""
    logger.debug(f"Received Event:{json.dumps(event)}")
    logger.debug(f"Forwarder version: {DD_FORWARDER_VERSION}")

    if DD_ADDITIONAL_TARGET_LAMBDAS:
        invoke_additional_target_lambdas(event)

    metrics, logs, trace_payloads = split_events(
        transform_events(enrich_events(parse_event(event, context)))
    )

    if DD_FORWARD_LOG:
        forward_logs(logs)

    forward_metrics(metrics)

    if len(trace_payloads) > 0:
        forward_traces(trace_payloads)

    parse_and_submit_enhanced_metrics(logs)


lambda_handler = datadog_lambda_wrapper(datadog_forwarder)


def invoke_additional_target_lambdas(event):
    lambda_client = boto3.client("lambda")
    lambda_arns = DD_ADDITIONAL_TARGET_LAMBDAS.split(",")
    lambda_payload = json.dumps(event)

    for lambda_arn in lambda_arns:
        lambda_client.invoke(
            FunctionName=lambda_arn,
            InvocationType="Event",
            Payload=lambda_payload,
        )

    return


def split_events(events):
    """Split events into metrics, logs, and trace payloads"""
    metrics, logs, trace_payloads = [], [], []
    for event in events:
        metric = extract_metric(event)
        trace_payload = extract_trace_payload(event)
        if metric:
            metrics.append(metric)
        elif trace_payload:
            trace_payloads.append(trace_payload)
        else:
            logs.append(event)

    logger.debug(
        f"Extracted {len(metrics)} metrics, {len(trace_payloads)} "
        f"traces, and {len(logs)} logs"
    )

    return metrics, logs, trace_payloads


def json_loads(message):
    try:
        return json.loads(message)
    except json.decoder.JSONDecodeError as exc:
        logger.info(str(exc))
        return None


def extract_metric(event):
    """Extract metric from an event if possible"""

    message = event.get("message")
    if message is None:
        return None

    metric = json_loads(message)
    if metric is None:
        return None

    required_attrs = {"m", "v", "e", "t"}
    if not all(attr in metric for attr in required_attrs):
        return None
    if not isinstance(metric["t"], list):
        return None
    if not (isinstance(metric["v"], int) or isinstance(metric["v"], float)):
        return None

    lambda_log_metadata = event.get("lambda", {})
    lambda_log_arn = lambda_log_metadata.get("arn")

    if lambda_log_arn:
        metric["t"] += [f"function_arn:{lambda_log_arn.lower()}"]

    metric["t"] += event[DD_CUSTOM_TAGS].split(",")
    return metric


def extract_trace_payload(event):
    """Extract trace payload from an event if possible"""
    message = event["message"]

    obj = json_loads(message)
    if obj is None:
        return None

    # check that the log is not containing a trace array unrelated to Datadog
    trace_id_found = (
        "traces" in obj
        and isinstance(obj["traces"], list)
        and len(obj["traces"]) > 0
        and isinstance(obj["traces"][0], list)
        and obj["traces"][0][0]["trace_id"] is not None
    )

    if trace_id_found:
        return {"message": message, "tags": event[DD_CUSTOM_TAGS]}
    return None


def transform_events(events):
    """Performs transformations on complex events

    Ex: handles special cases with nested arrays of JSON objects
    Args:
        events (dict[]): the list of event dicts we want to transform
    """
    for event in reversed(events):
        findings = separate_security_hub_findings(event)
        if findings:
            events.remove(event)
            events.extend(findings)

        waf = parse_aws_waf_logs(event)
        if waf != event:
            events.remove(event)
            events.append(waf)
    return events


def enrich_events(events):
    """Adds event-specific tags and attributes to each event

    Args:
        events (dict[]): the list of event dicts we want to enrich
    """
    for event in events:
        add_metadata_to_lambda_log(event)
        extract_ddtags_from_message(event)
        extract_host_from_cloudtrails(event)
        extract_host_from_guardduty(event)
        extract_host_from_route53(event)

    return events


def add_metadata_to_lambda_log(event):
    """Mutate log dict to add tags, host, and service metadata

    * tags for functionname, aws_account, region
    * host from the Lambda ARN
    * service from the Lambda name

    If the event arg is not a Lambda log then this returns without doing anything

    Args:
        event (dict): the event we are adding Lambda metadata to
    """
    lambda_log_metadata = event.get("lambda", {})
    lambda_log_arn = lambda_log_metadata.get("arn")

    # Do not mutate the event if it's not from Lambda
    if not lambda_log_arn:
        return

    # Set Lambda ARN to "host"
    event[DD_HOST] = lambda_log_arn

    # Function name is the seventh piece of the ARN
    function_name = lambda_log_arn.split(":")[6]
    tags = [f"functionname:{function_name}"]

    # Get custom tags of the Lambda function
    custom_lambda_tags = get_enriched_lambda_log_tags(event)

    # Set the `service` tag and metadata field. If the Lambda function is
    # tagged with a `service` tag, use it, otherwise use the function name.
    service_tag = next(
        (tag for tag in custom_lambda_tags if tag.startswith("service:")),
        f"service:{function_name}",
    )
    tags.append(service_tag)
    event[DD_SERVICE] = service_tag.split(":")[1]

    # Check if one of the Lambda's custom tags is env
    # If an env tag exists, remove the env:none placeholder
    custom_env_tag = next(
        (tag for tag in custom_lambda_tags if tag.startswith("env:")), None
    )
    if custom_env_tag is not None:
        event[DD_CUSTOM_TAGS] = event[DD_CUSTOM_TAGS].replace("env:none", "")

    tags += custom_lambda_tags

    # Dedup tags, so we don't end up with functionname twice
    tags = list(set(tags))
    tags.sort()  # Keep order deterministic

    event[DD_CUSTOM_TAGS] = ",".join([event[DD_CUSTOM_TAGS]] + tags)


def extract_ddtags_from_message(event):
    """When the logs intake pipeline detects a `message` field with a
    JSON content, it extracts the content to the top-level. The fields
    of same name from the top-level will be overridden.

    E.g. the application adds some tags to the log, which appear in the
    `message.ddtags` field, and the forwarder adds some common tags, such
    as `aws_account`, which appear in the top-level `ddtags` field:

    {
        "message": {
            "ddtags": "mytag:value", # tags added by the application
            ...
        },
        "ddtags": "env:xxx,aws_account", # tags added by the forwarder
        ...
    }

    Only the custom tags added by the application will be kept.

    We might want to change the intake pipeline to "merge" the conflicting
    fields rather than "overridding" in the future, but for now we should
    extract `message.ddtags` and merge it with the top-level `ddtags` field.
    """
    if "message" in event and DD_CUSTOM_TAGS in event["message"]:
        extracted_ddtags = None
        if isinstance(event["message"], dict):
            extracted_ddtags = event["message"].pop(DD_CUSTOM_TAGS)
        elif isinstance(event["message"], str):
            message_dict = json.loads(event["message"])
            extracted_ddtags = message_dict.pop(DD_CUSTOM_TAGS)
            event["message"] = json.dumps(message_dict)
        else:
            raise ValueError(f"Unknown event message: {json.dumps(event)}")

        if extracted_ddtags:
            event[DD_CUSTOM_TAGS] = f"{event[DD_CUSTOM_TAGS]},{extracted_ddtags}"


def extract_host_from_cloudtrails(event):
    """Extract the hostname from cloudtrail events userIdentity.arn field if it
    matches AWS hostnames.

    In case of s3 events the fields of the event are not encoded in the
    "message" field, but in the event object itself.
    """

    if event is not None and event.get(DD_SOURCE) == "cloudtrail":
        message = event.get("message", {})
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError:
                logger.debug("Failed to decode cloudtrail message")
                return

        # deal with s3 input type events
        if not message:
            message = event

        if isinstance(message, dict):
            arn = message.get("userIdentity", {}).get("arn")
            if arn is not None:
                match = HOST_IDENTITY_REGEXP.match(arn)
                if match is not None:
                    event[DD_HOST] = match.group("host")


def extract_host_from_guardduty(event):
    if event is not None and event.get(DD_SOURCE) == "guardduty":
        host = event.get("detail", {}).get("resource")
        if isinstance(host, dict):
            host = host.get("instanceDetails", {}).get("instanceId")
            if host is not None:
                event[DD_HOST] = host


def extract_host_from_route53(event):
    if event is not None and event.get(DD_SOURCE) == "route53":
        message = event.get("message", {})
        if isinstance(message, str):
            try:
                message = json.loads(message)
            except json.JSONDecodeError:
                logger.debug("Failed to decode Route53 message")
                return

        if isinstance(message, dict):
            host = message.get("srcids", {}).get("instance")
            if host is not None:
                event[DD_HOST] = host


def forward_metrics(metrics):
    """
    Forward custom metrics submitted via logs to Datadog in a background thread
    using `lambda_stats` that is provided by the Datadog Python Lambda Layer.
    """
    logger.debug(f"Forwarding {len(metrics)} metrics")

    for metric in metrics:
        lambda_stats.distribution(
            metric["m"], metric["v"], timestamp=metric["e"], tags=metric["t"]
        )

        logger.debug(f"Forwarded metric: {json.dumps(metric)}")

    lambda_stats.distribution(
        "{}.metrics_forwarded".format(DD_FORWARDER_TELEMETRY_NAMESPACE_PREFIX),
        len(metrics),
        tags=get_forwarder_telemetry_tags(),
    )


def forward_traces(trace_payloads):
    logger.debug(f"Forwarding {len(trace_payloads)} traces")

    trace_connection.send_traces(trace_payloads)

    logger.debug(f"Forwarded traces: {json.dumps(trace_payloads)}")

    lambda_stats.distribution(
        "{}.traces_forwarded".format(DD_FORWARDER_TELEMETRY_NAMESPACE_PREFIX),
        len(trace_payloads),
        tags=get_forwarder_telemetry_tags(),
    )
