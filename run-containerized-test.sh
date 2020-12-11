#!/bin/bash -x
if ! docker build --tag dynamodb-user-manager:amazonlinux2 \
       --file amazonlinux-setup.dockerfile .; then
    exit $?;
fi;

docker run --rm --volume=${PWD}/docker-export:/export:rw dynamodb-user-manager:amazonlinux2
result=$?
if [[ -f docker-export/.coverage ]]; then
  cp docker-export/.coverage .coverage
  CONTAINER_BUILD_PATH="/home/builder/dynamodb-user-manager"
  echo "UPDATE file SET path = '$PWD/' || substr(path, length('$CONTAINER_BUILD_PATH/') + 1) WHERE path LIKE '$CONTAINER_BUILD_PATH/%';" | sqlite3 -batch .coverage
  # sed -e "s,/,$PWD/,g" docker-export/.coverage > .coverage
fi;
exit $?
