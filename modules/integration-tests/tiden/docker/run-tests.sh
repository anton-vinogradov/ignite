#!/usr/bin/env bash

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" # "

. ${SCRIPT_DIR}/consts.sh
. ${SCRIPT_DIR}/utils.sh

run_suite() {
    local suite="${1}"
    shift
    docker exec \
        --user tiden \
        tiden-master \
        bash -c "\
            cd /home/tiden; \
            tiden \
                run-tests \
                    \$(for i in config/*; do echo \"--tc=\$i\"; done) \
                    --ts=$suite \
                    ${@}"
}

run_ignite_suite() {
    local suite="${1}"
    local ignite_version="${2}"
    run_suite \
        ${suite} \
        --to=test_ignite_version=${ignite_version} \
        --to=xunit_file=xunit_${suite}_${ignite_version/./_}.xml \
        --to=testrail_report=var/report_${suite}_${ignite_version/./_}.yaml
}

