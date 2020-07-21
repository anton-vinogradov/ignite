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

ARG JDK_VERSION=openjdk:8

FROM $JDK_VERSION

ARG TINI_VERSION="v0.19.0"
ARG USERUID=1000
ARG USERGID=1000
ARG TIDEN_IMAGE_TIMESTAMP=0
LABEL tiden.image.timestamp=$TIDEN_IMAGE_TIMESTAMP

COPY --from=tiden-base /root/.ssh/* /root/.ssh/

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
            libffi-dev \
            libssl-dev \
            psmisc \
            coreutils \
            netcat \
            iptables \
            jq \
            net-tools \
            vim \
            cmake \
            pkg-config \
            libfuse-dev \
            iperf \
            tcpdump \
            net-tools \
            traceroute \
            mc \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && mkdir -p /root/.ssh/ \
    && mkdir -p /var/run/sshd \
    && echo 'PermitUserEnvironment yes' >> /etc/ssh/sshd_config \
    && sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd \
    && echo 'tiden ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers \
    && mkdir -p /home/tiden/.ssh \
    && rsync -aiq /root/.ssh/ /home/tiden/.ssh \
    && echo "PATH=$(runuser -l tiden -c 'echo $PATH'):$JAVA_HOME/bin" >> /home/tiden/.ssh/environment \
    && echo 'PATH=$PATH:'"$JAVA_HOME/bin" >> /home/tiden/.profile \
    && chown -R tiden:tiden /home/tiden/ /mnt/ /var/log/ \
    && wget -O /tini https://github.com/krallin/tini/releases/download/$TINI_VERSION/tini \
    && chmod +x /tini


EXPOSE 22

ENTRYPOINT ["/tini", "-g", "--"]

CMD ["/usr/sbin/sshd", "-D"]
