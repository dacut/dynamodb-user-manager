#!/bin/bash -x
if ! docker build --tag dynamodb-user-manager:amazonlinux2 \
       --file amazonlinux-setup.dockerfile .; then
    exit $?;
fi;

docker run --rm --volume=${PWD}/docker-export:/export:rw dynamodb-user-manager:amazonlinux2
result=$?
if [[ -f docker-export/.coverage ]]; then
  sed -e "s,/home/builder/dynamodb-user-manager/,$PWD/,g" docker-export/.coverage > .coverage
fi;
exit $?
