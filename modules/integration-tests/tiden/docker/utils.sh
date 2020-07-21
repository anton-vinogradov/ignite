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

. ${SCRIPT_DIR}/../utils.sh

have_volume() {
  local volume_name="${1}"

  docker volume inspect ${volume_name} >/dev/null 2>/dev/null
}

have_docker_image() {
  local image_name="${1}"
  [ ! "${image_name}" = "" ] \
  && [ $(docker images -f reference="${image_name}" -q | wc -l) -gt 0 ]
}

have_docker_container() {
  local container_name="${1}"
  docker container inspect ${container_name} >/dev/null 2>/dev/null
}

stop_and_remove_container() {
  local container_name="${1}"

  if have_docker_container ${container_name}; then
      docker stop ${container_name} >/dev/null 2>/dev/null \
      && docker rm ${container_name} >/dev/null 2>/dev/null
  fi
}

remove_docker_image() {
  local image_name="${1}"
  if have_docker_image ${image_name}; then
    docker rmi ${image_name} >/dev/null 2>/dev/null
  fi
}

