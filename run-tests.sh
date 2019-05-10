#!/bin/bash -ex
sudo groupadd --gid 5000 testuser5000
sudo useradd --comment "Test User 5000" --home-dir /home/testuser5000 \
    --gid 5000 --uid 5000 --shell /bin/true --groups ftp,video,tape testuser5000
sudo chage --lastday 2001-01-01 --expiredate 2100-01-01 --inactive 50 \
    --mindays 10 --maxdays 2000 --warndays 14 testuser5000
sudo --preserve-env $VIRTUAL_ENV/bin/nosetests --with-coverage \
    --cover-package dynamodbusermanager --nocapture --process-timeout 10 \
    tests
