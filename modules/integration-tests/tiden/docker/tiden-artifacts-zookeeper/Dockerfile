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

FROM tiden-artifacts-fetcher

ARG APACHE_MIRROR="https://apache-mirror.rbc.ru/pub/apache"

RUN . /opt/utils.sh \
    && fetch_artifact \
        "${ARTIFACT_NAME}-${ARTIFACT_VERSION}.tar.gz" \
        "${APACHE_MIRROR}/${ARTIFACT_NAME}/${ARTIFACT_NAME}-${ARTIFACT_VERSION}" \
        "${ARTIFACT_NAME}" \
        "${ARTIFACT_VERSION}"

RUN cd /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION} \
    && rm -rf \
        dist-maven \
        src \
        docs \
        recipes \
        contrib \
        zookeeper-client \
        zookeeper-docs \
        zookeeper-it \
        zookeeper-recipes \
        zookeeper-server \
        *.txt *.xml *.asc *.md5 *.sha1 2>/dev/null \
    && echo -e -n "\
artifacts:\n\
  ${ARTIFACT_NAME}-${ARTIFACT_VERSION}:\n\
    type: zookeeper\n\
    glob_path: ftp\n\
    path: /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}/\n\
    remote_path: /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}/\n\
    symlink_dirs: \n\
      - bin\n\
      - conf\n\
      - lib\n\
" > /opt/config-artifacts-${ARTIFACT_NAME}-${ARTIFACT_VERSION}.yaml

VOLUME /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}
