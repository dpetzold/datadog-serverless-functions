# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2021 Datadog, Inc.
from setuptools import setup

setup(
    name="aws-datadog-forwarder",
    version="0.0.0.dev0",
    description="Datadog AWS Forwarder Lambda Function",
    url="https://github.com/DataDog/datadog-serverless-functions/tree/master/aws/logs_monitoring",
    author="Datadog, Inc.",
    author_email="dev@datadoghq.com",
    packages=[
        "datadog_forwarder",
    ],
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="datadog aws lambda layer",
    python_requires=">=3.7, =<3.9",
    install_requires=[
        "boto3==1.24.24",
        "datadog-lambda==3.60.0",
        "humanize==4.2.3",
        "requests==2.28.1",
        "requests-futures==1.0.0",
    ],
    extras_require={
        "dev": [
            "nose2==0.9.1",
            "flake8==4.0.1",
        ]
    },
)
