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

main() {
  prepare_config_directory

  stop_master
  stop_slaves
  destroy_network

  create_network
  run_master

  run_slaves ignite server 4
  run_slaves ignite client 2
}

prepare_config_directory() {
  mkdir -p ${TIDEN_CONFIG_DIR}
  mkdir -p ${TIDEN_VAR_DIR}

  for ignite_version in ${PREV_IGNITE_VERSION}; do
    prepare_artifact ignite ${ignite_version}
  done

  prepare_artifact spark ${SPARK_VERSION}

  prepare_artifact ignite dev ${IGNITE_SOURCE_DIR}

  cp -f ${IGNITE_SOURCE_DIR}/modules/integration-tests/tiden/docker/config/* ${TIDEN_CONFIG_DIR}/
}

prepare_artifact() {
  local artifact_name="${1}"
  local artifact_version="${2}"
  local artifact_volume_name="${3}"
  if ! have_volume "tiden-artifacts-${artifact_name}-${artifact_version}"; then
      log_info "preparing artifact: ${artifact_name} ${artifact_version}"

      if [ "$artifact_volume_name" = "" ]; then
        artifact_volume_name="tiden-artifacts-${artifact_name}-${artifact_version}"
      fi

      docker run \
        --rm \
        -v $artifact_volume_name:/opt/${artifact_name}-${artifact_version} \
        tiden-artifacts-${artifact_name}:${artifact_version} \
        >$TIDEN_CONFIG_DIR/artifacts-${artifact_name}-${artifact_version}.yaml
   fi
}

destroy_network() {
  if docker network inspect tiden &>/dev/null; then
    log_info "destroying Tiden network"
    docker network rm tiden >/dev/null
  fi
}

create_network() {
  log_info "creating Tiden network"
  docker network create tiden >/dev/null
}

tiden_artifacts() {
  local opt='ro'
  if [ "$osname" = "Darwin" ]; then
    opt="$opt,delegated"
  fi
  local artifact_volumes="-v $IGNITE_SOURCE_DIR:/opt/ignite-dev:${opt}"
  for ignite_version in $PREV_IGNITE_VERSION; do
    artifact_volumes="$artifact_volumes -v tiden-artifacts-ignite-$ignite_version:/opt/ignite-${ignite_version}:${opt}"
  done
  artifact_volumes="$artifact_volumes -v tiden-artifacts-spark-$SPARK_VERSION:/opt/spark-$SPARK_VERSION:${opt}"
  echo $artifact_volumes
}

stop_master() {
  if docker container inspect tiden-master &>/dev/null; then
    log_info "destroying Tiden master"
    docker stop tiden-master >/dev/null
    docker rm tiden-master >/dev/null
  fi
}

stop_slaves() {
  local container_names=$(docker ps -f name=tiden-slave --format '{{.Names}}' -q -a)
  if [ ! "$container_names" = "" ]; then
    log_info "destroying Tiden slaves"
    docker stop $container_names >/dev/null
    docker rm $container_names >/dev/null
  fi
}

run_master() {
  log_info "running Tiden master '${TIDEN_VERSION}'"
  local tiden_sources_volume=""
  if [ "$TIDEN_VERSION" = "develop" ]; then
    if [ "$TIDEN_SOURCES_DIR" = "" -o ! -d "$TIDEN_SOURCES_DIR" ]; then
      log_error "to run 'develop' version of Tiden, you must set TIDEN_SOURCES_DIR shell variable"
      exit 1
    fi
    tiden_sources_volume="-v $TIDEN_SOURCES_DIR:/src"
  fi
  docker run \
    --name tiden-master \
    -h tiden-master \
    -t \
    -d \
    --network tiden \
    $(tiden_artifacts) \
    $tiden_sources_volume \
    -v tiden-ssh-credentials:/root/.ssh \
    -v $TIDEN_CONFIG_DIR:/home/tiden/config \
    -v $TIDEN_APPS_DIR:/home/tiden/apps \
    -v $TIDEN_SUITES_DIR:/home/tiden/suites \
    -v $TIDEN_VAR_DIR:/home/tiden/var \
    tiden-master:${TIDEN_VERSION} \
    >/dev/null
}

tiden_slave_get_ip() {
  docker inspect --format='{{range .NetworkSettings.Networks}}{{print .IPAddress}}{{end}}' "tiden-slave-${1}-${2}-${3}"
}

run_slaves() {
  local app_name="${1}"
  local app_mode="${2}"
  local slave_num="${3}"
  if [ "$slave_num" = "" ]; then
    log_error "slave_num must be > 0"
    exit 1
  fi
  log_info "running $slave_num Tiden slave(s) for '$app_name' $app_mode with JDK '${jdk_version}'"
  slave_image="tiden-slave:${jdk_version}"
  slave_ips=""
  for i in $(seq 1 $slave_num); do
    run_slave $i $slave_image "$app_name-$app_mode"
    slave_ip=$(tiden_slave_get_ip "${app_name}" "${app_mode}" "${i}")
    if [ "$slave_ips" = "" ]; then
      slave_ips="$slave_ip"
    else
      slave_ips="$slave_ips,$slave_ip"
    fi
  done
  (
    if [ "$app_name" = "ignite" ]; then
      echo -en "environment:\n  ${app_mode}_hosts: $slave_ips\n"
    else
      echo -en "environment:\n  ${app_name}:\n    ${app_mode}_hosts: $slave_ips\n"
    fi
  ) >$TIDEN_CONFIG_DIR/env_${app_name}_${app_mode}.yaml
}

run_slave() {
  local slave_num="${1}"
  local slave_image="${2}"
  local slave_name="${3}"
  docker run \
    --name tiden-slave-${slave_name}-${slave_num} \
    -h tiden-slave-${slave_name}-${slave_num} \
    -t \
    -d \
    --network tiden \
    -v tiden-ssh-credentials:/root/.ssh \
    $(tiden_artifacts) \
    ${slave_image} \
    >/dev/null
}

main
