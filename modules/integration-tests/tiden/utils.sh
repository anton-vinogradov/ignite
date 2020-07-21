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

readlink_f_linux() {
   readlink -f "$1"
}

readlink_f_macos() {
    # https://stackoverflow.com/questions/1055671/how-can-i-get-the-behavior-of-gnus-readlink-f-on-a-mac
    local TARGET_FILE="$1"
    pushd . >/dev/null
    cd `dirname ${TARGET_FILE}`
    TARGET_FILE=`basename ${TARGET_FILE}`

    # Iterate down a (possible) chain of symlinks
    while [ -L "${TARGET_FILE}" ]
    do
        TARGET_FILE=`readlink ${TARGET_FILE}`
        cd `dirname ${TARGET_FILE}`
        TARGET_FILE=`basename ${TARGET_FILE}`
    done

    # Compute the canonicalized name by finding the physical path
    # for the directory we're in and appending the target file.
    local PHYS_DIR=`pwd -P`
    local RESULT=${PHYS_DIR}/${TARGET_FILE}
    popd >/dev/null
    echo ${RESULT}
}

stat_c_linux() {
    stat -c %Y "$1"
}

stat_c_macos() {
    stat -f %m "$1"
}

user_uid_linux() {
    id -u
}

user_uid_macos() {
    echo 1000
}

user_gid_linux() {
    id -g
}

user_gid_macos() {
    echo 1000
}

osname=`uname`

readlink_f() {
    case ${osname} in
        Darwin*)
            readlink_f_macos "${@}"
            ;;
        *)
            readlink_f_linux "${@}"
            ;;
    esac
}

stat_c() {
    case ${osname} in
        Darwin*)
            stat_c_macos "${@}"
            ;;
        *)
            stat_c_linux "${@}"
            ;;
    esac
}

user_uid() {
    case ${osname} in
        Darwin*)
            user_uid_macos
            ;;
        *)
            user_uid_linux
            ;;
    esac
}

user_gid() {
    case ${osname} in
        Darwin*)
            user_gid_macos
            ;;
        *)
            user_gid_linux
            ;;
    esac
}

log_print() {
    echo -en $1
    shift
    echo " ${@}"
}

no_colors() {
    [ ! "$TEAMCITY_PROJECT_NAME" = "" -a "$JENKINS_URL" = "" ]
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
