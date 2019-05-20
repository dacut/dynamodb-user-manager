FROM amazonlinux:2ex
RUN yum update -y
RUN yum install -y less man python3 sudo strace util-linux-user
RUN pip3 install virtualenv
RUN useradd --comment "Build User" --home-dir /home/builder --create-home --groups wheel --system --user-group builder

# Don't require a password for wheel users
RUN sed -E -e 's/^%wheel/# %wheel/' -e 's/# (%wheel.*NOPASSWD: ALL)/\1/' /etc/sudoers > /etc/sudoers.new
RUN mv /etc/sudoers.new /etc/sudoers
RUN chmod 440 /etc/sudoers

USER builder:builder
WORKDIR /home/builder

# Cache a number of Python packages so we don't have to repeatedy download them
RUN pip3 install --user --upgrade boto3 coverage moto mypy nose pip pylint

RUN mkdir export
VOLUME [ "/export" ]

RUN mkdir dynamodb-user-manager
WORKDIR dynamodb-user-manager

COPY LICENSE ./
COPY README.md ./
RUN virtualenv venv
ENV VIRTUAL_ENV=/home/builder/dynamodb-user-manager/venv
ENV PATH=${VIRTUAL_ENV}/bin:$PATH
COPY requirements.txt ./
RUN pip install --requirement requirements.txt
#RUN BOTOCORE_DIR=$(ls -d venv/lib/python3.7/site-packages/botocore-*.dist-info); \
#    echo $BOTOCORE_DIR; \
#    mv $BOTOCORE_DIR/metadata.json $BOTOCORE_DIR/metadata.json.orig; \
#    mv $BOTOCORE_DIR/METADATA $BOTOCORE_DIR/METADATA.orig; \
#    sed -e 's/urllib3>=1.20,<1.25/urllib3>=1.20,<2.0/g' $BOTOCORE_DIR/metadata.json.orig > $BOTOCORE_DIR/metadata.json; \
#    sed -e 's/urllib3>=1.20,<1.25/urllib3>=1.20,<2.0/g' $BOTOCORE_DIR/METADATA.orig > $BOTOCORE_DIR/METADATA

COPY dynamodbusermanager dynamodbusermanager/
COPY setup.py ./
RUN ./setup.py build
RUN ./setup.py install

COPY tests tests/
COPY run-tests.sh ./
CMD ./run-tests.sh