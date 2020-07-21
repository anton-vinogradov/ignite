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

fetch_artifact() {
    local ARTIFACT_ARCHIVE_NAME="${1}"
    local ARTIFACT_BASE_URL="${2}"
    local ARTIFACT_NAME="${3}"
    local ARTIFACT_VERSION="${4}"

    log_info "Fetching $ARTIFACT_BASE_URL/$ARTIFACT_ARCHIVE_NAME"

    wget \
        -t 5 \
        --retry-connrefused \
        --no-verbose \
        -O ${ARTIFACT_ARCHIVE_NAME} \
        ${ARTIFACT_BASE_URL}/$ARTIFACT_ARCHIVE_NAME

    if [ $? -ne 0 ]; then
        log_error "failed to download!"
        exit 1
    fi

    local archive_ext=$(echo $ARTIFACT_ARCHIVE_NAME | rev | cut -d '.' -f 1 | rev)
    local archive_name=$(echo $ARTIFACT_ARCHIVE_NAME | rev | cut -d '.' -f 2- | rev)

    if [ ! "${ARTIFACT_ARCHIVE_NAME/tar.gz/}" = "${ARTIFACT_ARCHIVE_NAME}" ]; then
      archive_ext=$(echo $ARTIFACT_ARCHIVE_NAME | rev | cut -d '.' -f 1-2 | rev)
      archive_name=$(echo $ARTIFACT_ARCHIVE_NAME | rev | cut -d '.' -f 3- | rev)
    fi

    case $archive_ext in
        tgz|tar.gz)
          tar --strip-components=1 -C /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}/ -xzf ${ARTIFACT_ARCHIVE_NAME} > /dev/null
          ;;
        zip)
          unzip ${ARTIFACT_ARCHIVE_NAME} > /dev/null \
          && mv -f /opt/${archive_name}/* /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}/ \
          && rm -rf /opt/${archive_name}
          ;;
        *)
          log_error "Unknown archive type: '$archive_ext'"
          exit 1
          ;;
    esac
    if [ $? -ne 0 ]; then
        log_error "failed to unpack ${ARTIFACT_ARCHIVE_NAME}"
        exit 1
    fi
    rm -f ${ARTIFACT_ARCHIVE_NAME}
    ls -la /opt
    cd /opt/${ARTIFACT_NAME}-${ARTIFACT_VERSION}
}

