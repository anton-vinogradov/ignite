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

ARG APACHE_ARCHIVE="https://archive.apache.org/dist"

RUN . /opt/utils.sh \
    && fetch_artifact \
        "apache-${ARTIFACT_NAME}-${ARTIFACT_VERSION}-bin.zip" \
        "$APACHE_ARCHIVE/${ARTIFACT_NAME}/${ARTIFACT_VERSION}" \
        "${ARTIFACT_NAME}" \
        "${ARTIFACT_VERSION}"

RUN cd /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION} \
    && rm -rf \
        docs \
    && ln -s optional/ignite-log4j libs/ignite-log4j \
    && unzip -d . ./libs/ignite-core-*.jar ignite.properties > /dev/null \
    && echo -e -n "\
artifacts:\n\
  ${ARTIFACT_NAME}-${ARTIFACT_VERSION}:\n\
    type: ignite\n\
    glob_path: ftp\n\
    path: /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}/\n\
    remote_path: /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}/\n\
    symlink_dirs: \n\
      - benchmarks\n\
      - bin\n\
      - config\n\
      - libs\n\
      - examples\n\
      - platforms\n\
" > /opt/config-artifacts-${ARTIFACT_NAME}-${ARTIFACT_VERSION}.yaml \
    && (cat ignite.properties \
        | grep -E "^ignite.(version|build|revision|rel.date)" \
        | sed "s/=/: /" \
        | sed "s/ignite./    ignite_/" \
        | sed "s/rel.date/rel_date/" \
        >> /opt/config-artifacts-${ARTIFACT_NAME}-${ARTIFACT_VERSION}.yaml) \
    && rm ignite.properties


VOLUME /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}
