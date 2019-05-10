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

RUN mkdir dynamodb-user-manager
WORKDIR dynamodb-user-manager

COPY LICENSE ./
COPY README.md ./
RUN virtualenv venv
ENV VIRTUAL_ENV=/home/builder/dynamodb-user-manager/venv
ENV PATH=${VIRTUAL_ENV}/bin:$PATH
COPY requirements.txt ./
RUN pip install --requirement requirements.txt

COPY dynamodbusermanager dynamodbusermanager/
COPY setup.py ./
RUN ./setup.py build
RUN ./setup.py install

COPY tests tests/
COPY run-tests.sh ./
CMD ./run-tests.sh