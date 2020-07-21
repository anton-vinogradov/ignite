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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"   # "

. ${SCRIPT_DIR}/../consts.sh
. ${SCRIPT_DIR}/utils.sh

export JDK_VERSION=openjdk:8

export TIDEN_CONFIG_DIR=$(readlink_f ${SCRIPT_DIR}/../../target)/tiden/config
export TIDEN_VAR_DIR=$(readlink_f ${SCRIPT_DIR}/../../target)/tiden/var
export IGNITE_SOURCE_DIR=$(readlink_f ${SCRIPT_DIR}/../../../..)
export TIDEN_SUITES_DIR=${IGNITE_SOURCE_DIR}/modules/integration-tests/tiden/suites
export TIDEN_APPS_DIR=${IGNITE_SOURCE_DIR}/modules/integration-tests/tiden/apps

if [ ! "${TIDEN_SOURCES_DIR}" = "" -a "${TIDEN_VERSION}" = "latest" ]; then
  export TIDEN_VERSION="develop"
fi
