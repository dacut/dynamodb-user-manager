#!/bin/bash -ex
docker build --tag dynamodb-user-manager:amazonlinux2 --file amazonlinux-setup.dockerfile .
docker run dynamodb-user-manager:amazonlinux2