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

ENTRYPOINT \
    if [ ! -d /opt/ignite-dev -o ! -f /opt/ignite-dev/pom.xml ]; then \
        echo "ERROR: to run this image you must mount Apache Ignite sources directory as '/opt/ignite-dev' volume"; \
        exit 1; \
    fi \
    && if [ ! -d /opt/ignite-dev/modules/core/target/classes -o ! -f /opt/ignite-dev/modules/core/target/classes/ignite.properties ]; then \
        echo "ERROR: to run this image you must first build Apache Ignite with 'scripts/build.sh'"; \
        exit 1; \
    fi \
    && echo -e -n "\
artifacts:\n\
  ignite-dev:\n\
    type: ignite\n\
    base: true\n\
    glob_path: ftp\n\
    path: /opt/ignite-dev/\n\
    remote_path: /opt/ignite-dev/\n\
    symlink_dirs: \n\
      - bin\n\
      - config\n\
      - modules\n\
      - examples\n\
" > /opt/config-artifacts-ignite-dev.yaml \
    && (cat /opt/ignite-dev/modules/core/target/classes/ignite.properties \
        | grep -E "^ignite.(version|build|revision|rel.date)" \
        | sed "s/=/: /" \
        | sed "s/ignite./    ignite_/" \
        | sed "s/rel.date/rel_date/" \
        >> /opt/config-artifacts-ignite-dev.yaml) \
    && cat /opt/config-artifacts-ignite-dev.yaml

VOLUME /opt/ignite-dev
