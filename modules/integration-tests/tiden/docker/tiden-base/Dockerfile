# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM python:3.7

ARG TINI_VERSION="v0.19.0"
ARG TIDEN_IMAGE_TIMESTAMP=0
LABEL tiden.image.timestamp=$TIDEN_IMAGE_TIMESTAMP
ARG USERUID=1000
ARG USERGID=1000

RUN    groupadd \
            -g $USERGID \
            tiden \
    && useradd \
            -ms /bin/bash \
            -g tiden \
            -u $USERUID \
            tiden \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            sudo \
            rsync \
            zip \
            unzip \
            wget \
            curl \
            openssh-server \
            python3.7-dev \
            libffi-dev \
            libssl-dev \
            psmisc \
            socat \
            vim \
            mc \
    && pip3.7 \
        install \
            --no-cache-dir \
            -q \
            --index-url https://pypi.org/simple/ \
            --extra-index-url https://test.pypi.org/simple/ \
        tiden \
    && pip3.7 uninstall -y tiden \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && mkdir -p /root/.ssh/ \
    && mkdir -p /var/run/sshd \
    && echo "\
\n\
Host *\n\
  ControlMaster auto\n\
  ControlPath ~/.ssh/master-%r@%h:%p\n\
  StrictHostKeyChecking no\n\
  ConnectTimeout=10\n\
  IdentityFile ~/.ssh/id_rsa\n" > /root/.ssh/config \
    && ssh-keygen -m PEM -q -t rsa -N '' -f /root/.ssh/id_rsa \
    && cp -f /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys \
    && echo 'PermitUserEnvironment yes' >> /etc/ssh/sshd_config \
    && sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd \
    && echo 'tiden ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers \
    && echo 'export SSH_AUTH_SOCK=/home/tiden/.ssh-agent/socket' >> /home/tiden/.profile \
    && mkdir -p /home/tiden/.ssh \
    && mkdir -p /home/tiden/.ssh-agent \
    && mkdir -p /home/tiden/config \
    && mkdir -p /home/tiden/suites \
    && mkdir -p /home/tiden/var \
    && rsync -aiq /root/.ssh/ /home/tiden/.ssh \
    && chown -R tiden:tiden /home/tiden/ /mnt/ /var/log/ \
    && wget -O /tini https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini \
    && chmod +x /tini

VOLUME ["/root/.ssh"]

EXPOSE 22

ENTRYPOINT ["/tini", "-g", "--"]

CMD /usr/sbin/sshd -D & /usr/bin/ssh-agent -a /home/tiden/.ssh-agent/socket -d
