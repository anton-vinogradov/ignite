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

FROM alpine

ARG USERUID=1000
ARG USERGID=1000
ARG TIDEN_IMAGE_TIMESTAMP=0
ENV TEAMCITY_PROJECT_NAME=''

LABEL tiden.image.timestamp=$TIDEN_IMAGE_TIMESTAMP
COPY *.sh /opt/

WORKDIR /opt

RUN    addgroup \
         -g $USERGID \
         tiden \
    && adduser \
         -s /bin/bash \
         -h /home/tiden \
         -G tiden \
         -u $USERUID \
         -S tiden \
    && chown -R tiden:tiden /opt \
    && ./apk_no_fail.sh update \
    && ./apk_no_fail.sh add --no-cache \
         wget \
         tar \
         unzip \
         bash

USER tiden

ONBUILD ARG ARTIFACT_NAME
ONBUILD ARG ARTIFACT_VERSION
ONBUILD ENV ARTIFACT_VERSION=${ARTIFACT_VERSION}
ONBUILD ENV ARTIFACT_NAME=${ARTIFACT_NAME}
ONBUILD ARG TIDEN_IMAGE_TIMESTAMP=0
ONBUILD LABEL tiden.image.timestamp=$TIDEN_IMAGE_TIMESTAMP
ONBUILD RUN mkdir -p /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}
ONBUILD CMD cat /opt/config-artifacts-${ARTIFACT_NAME}-${ARTIFACT_VERSION}.yaml

