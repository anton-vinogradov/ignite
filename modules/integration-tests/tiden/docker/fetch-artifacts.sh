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
export jdk_version=${JDK_VERSION/:/-}

## naive detection of user manual run - use Docker BuildKit for fancier output
#if [ "$MAVEN_CMD_LINE_ARGS" = "" -a "$TEAMCITY_PROJECT_NAME" = "" -a "$JENKINS_URL" = "" ]; then
#  export DOCKER_BUILDKIT=1
#fi

main() {
  build_tiden_images

  build_ignite_dev_image
  build_spark_image ${SPARK_VERSION}
  build_zookeeper_image ${ZOOKEEPER_VERSION}
  for ignite_version in ${PREV_IGNITE_VERSION}; do
    build_ignite_image ${ignite_version}
  done
}

build_tiden_images() {
  build_image tiden-artifacts-fetcher

  build_image tiden-base
  if [ "${TIDEN_VERSION}" = "develop" ]; then
    build_tiden_develop_image
  else
    local no_cache=''
    if [ "${TIDEN_VERSION}" = "latest" ]; then
        no_cache='--no-cache'
    fi
    build_image tiden-master tiden-master:${TIDEN_VERSION} --build-arg TIDEN_VERSION=${TIDEN_VERSION} ${no_cache}
  fi
  build_image tiden-slave tiden-slave:${jdk_version} --build-arg JDK_VERSION=${JDK_VERSION}
}

tiden_develop_image_timestamp() {
  tiden_image_timestamp tiden-master:develop
}

tiden_image_timestamp() {
  local image_name="${1}"
  docker inspect --format '{{ index .Config.Labels "tiden.image.timestamp"}}' ${image_name} 2>/dev/null
}

tiden_get_sources_timestamp() {
  local max_timestamp=0
  if which stat >/dev/null 2>/dev/null; then
    local current_timestamp=0
    for i in setup.py setup.cfg MANIFEST.in pyproject.toml requirements.txt tox.ini src/tiden/__version__.py; do
      if [ -f ${TIDEN_SOURCES_DIR}/$i ]; then
        current_timestamp=$(stat_c ${TIDEN_SOURCES_DIR}/$i 2>/dev/null)
        if [ ! "$current_timestamp" = "" ]; then
          if [ ${current_timestamp} -gt ${max_timestamp} ]; then
            max_timestamp=${current_timestamp}
          fi
        fi
      fi
    done
  fi
  echo ${max_timestamp}
}

get_sources_timestamp() {
  local max_timestamp=0
  if which stat >/dev/null 2>/dev/null; then
    local current_timestamp=0
    sources_path="${1}"
    for i in ${sources_path}/*; do
      current_timestamp=$(stat_c ${sources_path}/$i 2>/dev/null)
      if [ ! "$current_timestamp" = "" ]; then
        if [ ${current_timestamp} -gt ${max_timestamp} ]; then
          max_timestamp=${current_timestamp}
        fi
      fi
      if [ "$i" = "Dockerfile" ]; then
        local base_image_name=$(cat Dockerfile | grep FROM | cut -d ' ' -f 2)
        if [ -d ../${base_image_name} ]; then
          local base_image_timestamp=$(get_sources_timestamp ../${base_image_name})
          if [ ! "$base_image_timestamp" = "" ]; then
            if [ ${base_image_timestamp} -gt ${max_timestamp} ]; then
              max_timestamp=${base_image_timestamp}
            fi
          fi
        fi
      fi
    done
  fi
  echo ${max_timestamp}
}

build_tiden_develop_image() {
  # First detect if any of setup files was changed in order to trigger rebuild only if necessary.
  #
  # Simple relying on docker builder cache is not enough here, because we do build develop image via
  # running external builder container
  #
  local need_rebuild=1
  local develop_timestamp=$(tiden_get_sources_timestamp)

  if have_docker_image tiden-master:develop; then
    local image_timestamp=$(tiden_develop_image_timestamp)
    if [ ! "${image_timestamp}" = "" ]; then
      if [ ${image_timestamp} -ge ${develop_timestamp} ]; then
        need_rebuild=0
      fi
    fi
  fi

  if [ ${need_rebuild} -eq 1 ]; then
    log_info "Rebuilding 'tiden-master:develop' image"

    stop_and_remove_container tiden-master-builder
    remove_docker_image tiden-master-builder

    local develop_timestamp=$(tiden_get_sources_timestamp)
    build_image tiden-master-builder tiden-master-builder:latest --build-arg TIDEN_IMAGE_TIMESTAMP=${develop_timestamp}

    stop_and_remove_container tiden-master
    remove_docker_image tiden-master:develop

    docker \
      run \
        -d \
        --name tiden-master-builder \
        -v ${TIDEN_SOURCES_DIR}:/src \
        -v tiden-ssh-credentials:/root/.ssh \
        tiden-master-builder

    docker \
      exec \
        tiden-master-builder \
        bash -x /opt/install_develop.sh

    docker \
      stop \
        tiden-master-builder

    docker \
      commit \
        tiden-master-builder \
        tiden-master:develop

    docker \
      rm \
        tiden-master-builder
  fi
}

have_timestamp_arg() {
    local s=0
    while [ $# -gt 0 ]; do
        if [ "$1" == "--build-arg" -a $s -eq 0 ]; then
          s=1
        elif [ $s -eq 1 ]; then
          if [ ! "${1/TIDEN_IMAGE_TIMESTAMP/}" = "${1}" ]; then
            return 0
          fi
        fi
        shift
    done
    return 1
}

have_no_cache_arg() {
    while [ $# -gt 0 ]; do
        if [ "$1" == "--no-cache" ]; then
            return 0
        fi
        shift
    done
    return 1
}

build_image() {
  local image_base_dir="${1}"
  if [ "${image_base_dir}" = "" ]; then
    log_error "must give image base directory"
    exit 1
  fi
  if [ ! -d ${image_base_dir} ]; then
    log_error "unknown image directory ${image_base_dir}"
    exit 1
  fi
  shift
  local image_tag="${1}"
  if [ "$image_tag" = "" ]; then
    image_tag="${image_base_dir}:latest"
  else
    shift
  fi

  pushd ${image_base_dir} >/dev/null
  local need_rebuild=1
  local sources_timestamp=$(get_sources_timestamp .)

  if have_docker_image ${image_tag}; then
    if ! have_no_cache_arg "${@}"; then
      local image_timestamp=$(tiden_image_timestamp ${image_tag})

      if [ ! "${image_timestamp}" = "" ]; then
        if [ ${image_timestamp} -ge ${sources_timestamp} ]; then
          need_rebuild=0
        fi
      fi
    fi
  fi

  if [ $need_rebuild -eq 1 ]; then
      log_info "building image '$image_tag'"

      local timestamp="--build-arg TIDEN_IMAGE_TIMESTAMP=${sources_timestamp}"
      if have_timestamp_arg "${@}"; then
        timestamp=""
      fi

      docker \
        build \
          -t ${image_tag} \
          --build-arg USERUID="$(user_uid)" \
          --build-arg USERGID="$(user_gid)" \
          ${timestamp} \
          "${@}" .

  fi
  popd >/dev/null
}

build_artifact_image() {
  local ARTIFACT_NAME="${1}"
  local ARTIFACT_VERSION="${2}"

  if [ "${ARTIFACT_NAME}" = "" ]; then
    log_error "must specify ARTIFACT_NAME"
    exit 1
  fi

  if [ "${ARTIFACT_VERSION}" = "" ]; then
    log_error "must specify ARTIFACT_VERSION for artifact '${ARTIFACT_NAME}'"
    exit 1
  fi

  build_image \
    tiden-artifacts-${ARTIFACT_NAME} \
    tiden-artifacts-${ARTIFACT_NAME}:${ARTIFACT_VERSION} \
    --build-arg ARTIFACT_NAME=${ARTIFACT_NAME} \
    --build-arg ARTIFACT_VERSION=${ARTIFACT_VERSION}
}

build_ignite_image() {
  local IGNITE_VERSION="${1}"
  build_artifact_image ignite ${IGNITE_VERSION}
}

build_spark_image() {
  local SPARK_VERSION="${1}"
  build_artifact_image spark ${SPARK_VERSION}
}

build_zookeeper_image() {
  local ZOOKEEPER_VERSION="${1}"
  build_artifact_image zookeeper ${ZOOKEEPER_VERSION}
}

build_ignite_dev_image() {
  build_image tiden-artifacts-ignite-dev tiden-artifacts-ignite:dev
}

main
