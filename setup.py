#!/usr/bin/env python3
from setuptools import setup

setup(
    name="dynamodb-user-manager",
    description="Manage the local user database from DynamoDB",
    version="0.1",
    packages=["dynamodbusermanager"],
    entry_points={
        "console_scripts": [
            "dynamodb-user-manager = dynamodbusermanager.cli:main"
        ]
    },
    install_requires=["boto3>=1.9","requests<=2.21","urllib3>=1.20,<1.25"],
    tests_require=["coverage>=4.5.3", "moto>=1.3.8", "mypy>=0.701", "nose>=1.3.7", "pylint>=2.3.1"],
    python_requires=">=3.6",
    zip_safe=False,
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    license="Apache-2.0",
    url="https://github.com/dacut/dynamodb-user-manager",
)
