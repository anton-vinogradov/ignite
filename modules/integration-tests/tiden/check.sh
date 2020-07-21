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

MAVEN_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"   # "

. ${MAVEN_SCRIPT_DIR}/consts.sh
. ${MAVEN_SCRIPT_DIR}/utils.sh

log_info "Running $(basename $0)"

VAR_DIR=$(readlink_f ${MAVEN_SCRIPT_DIR}/../target/tiden/var)

if [ ! -d ${VAR_DIR} ]; then
    log_error "var directory '${VAR_DIR}' not found, run tests first"
    exit 1
fi

num_reports=$(find ${VAR_DIR}/ -name "*.yaml" -print | wc -l)
if [ ${num_reports} -eq 0 ]; then
    log_error "test run reports not found in '${VAR_DIR}', run tests first"
    exit 2
fi

find ${VAR_DIR}/ -name "*.yaml" -print | while read report_name; do
    log_info "checking ${report_name} ..."

    has_fail=$(cat ${report_name} | grep "last_status: failed" 2>/dev/null | wc -l)
    if [ ${has_fail} -gt 0 ]; then
        log_error "failed integration tests detected!"
        exit 3
    fi
done
