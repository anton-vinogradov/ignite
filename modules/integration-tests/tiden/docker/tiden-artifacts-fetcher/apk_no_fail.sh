#!/bin/sh

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

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)" # "

. ${SCRIPT_DIR}/utils.sh

# simple script to retry apk command due to there's well-known issues with Alpine CDN

n_tries=0
max_tries=5
while true; do
    apk "${@}"
    res=$?
    if [ $res -eq 0 ]; then
        break
    fi
    log_warn "retrying after 3 sec"
    sleep 3
    n_tries=$((n_tries + 1))
    if [ $n_tries -ge $max_tries ]; then
        log_error "apk fails to execute '${@}' after $max_tries retries"
        exit 1
    fi
done
