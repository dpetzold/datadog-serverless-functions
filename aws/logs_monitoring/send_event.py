import boto3
import time
import json

event = {
    "instant": {"epochSecond": 1657835117, "nanoOfSecond": 448000000},
    "level": "INFO",
    "thread": "http-nio-8080-exec-1",
    "mdc": {"dd.span_id": "4590903637024496412", "dd.trace_id": "9221531738328924905"},
    "loggerName": "com.shopstyle.dgs.foundation.config.DgsAppConfiguration",
    "message": "PersistQuery PreparsedDoc Cache HitStats: CacheStats{hitCount=51694, missCount=98, loadSuccessCount=48, loadFailureCount=0, totalLoadTime=189812179, evictionCount=47, evictionWeight=47}",
    "context": "default",
}


def main():
    client = boto3.client("logs")

    log_group_name = "ss-favorite-dgs-iapi-dev-weboutput"

    # client.create_log_stream(logGroupName=log_group_name, logStreamName="teststream")

    client.put_log_events(
        logGroupName=log_group_name,
        logStreamName="teststream",
        logEvents=[
            {"timestamp": int(time.time()), "message": json.dumps(event)},
        ],
    )


main()
