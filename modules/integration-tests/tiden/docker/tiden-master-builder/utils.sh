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

log_print() {
    echo -en $1
    shift
    echo " ${@}"
}

no_colors() {
    [ ! "${TEAMCITY_PROJECT_NAME:-}" = "" ]
}

log_info() {
    if no_colors; then
        log_print "[INFO]" "${@}"
    else
        log_print "[\033[1;34mINFO\033[0m]" "${@}"
    fi
}

log_error() {
    if no_colors; then
        log_print "[ERROR]" "${@}"
    else
        log_print "[\033[1;31mERROR\033[0m]" "${@}"
    fi
}

log_warn() {
    if no_colors; then
        log_print "[WARNING]" "${@}"
    else
        log_print "[\033[1;33mWARNING\033[0m]" "${@}"
    fi
}
