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

"""
This module contains the base class to build Ignite aware application written on java.
"""

import re

# pylint: disable=W0622
from ducktape.errors import TimeoutError

from ignitetest.services.ignite_execution_exception import IgniteExecutionException
from ignitetest.services.utils.ignite_aware import IgniteAwareService


class IgniteApplicationService(IgniteAwareService):
    """
    The base class to build Ignite aware application written on java.
    """

    SERVICE_JAVA_CLASS_NAME = "org.apache.ignite.internal.ducktest.utils.IgniteAwareApplicationService"

    # pylint: disable=R0913
    def __init__(self, context, config, java_class_name, num_nodes=1, params="", timeout_sec=60, modules=None,
                 servicejava_class_name=SERVICE_JAVA_CLASS_NAME, jvm_opts=None, start_ignite=True):
        super().__init__(context, config, num_nodes, modules=modules, servicejava_class_name=servicejava_class_name,
                         java_class_name=java_class_name, params=params, jvm_opts=jvm_opts, start_ignite=start_ignite)

        self.servicejava_class_name = servicejava_class_name
        self.java_class_name = java_class_name
        self.timeout_sec = timeout_sec
        self.params = params

    def start(self):
        self.start_async()
        self.await_started()

    def await_started(self):
        """
        Awaits start finished.
        """
        self.logger.info("Waiting for Ignite aware Application (%s) to start..." % self.java_class_name)

        self.await_event("Topology snapshot", self.timeout_sec, from_the_beginning=True)

        self.__check_status("IGNITE_APPLICATION_INITIALIZED", timeout=self.timeout_sec)

    # pylint: disable=W0221
    def stop_node(self, node, clean_shutdown=True):
        """
        Stops node in async way.
        """
        self.logger.info("%s Stopping node %s" % (self.__class__.__name__, str(node.account)))
        node.account.kill_java_processes(self.servicejava_class_name, clean_shutdown=clean_shutdown,
                                         allow_fail=True)

    def await_stopped(self, timeout_sec=10):
        """
        Awaits node stop finish.
        """
        for node in self.nodes:
            stopped = self.wait_node(node, timeout_sec=timeout_sec)
            assert stopped, "Node %s: did not stop within the specified timeout of %s seconds" % \
                            (str(node.account), str(timeout_sec))

        self.__check_status("IGNITE_APPLICATION_FINISHED", timeout=timeout_sec)

    # pylint: disable=W0221
    def stop(self, clean_shutdown=True, timeout_sec=10):
        """
        Stop services.
        """
        if clean_shutdown:
            self.stop_async(clean_shutdown)
            self.await_stopped(timeout_sec)
        else:
            self.stop_async(clean_shutdown)

    def __check_status(self, desired, timeout=1):
        self.await_event("%s\\|IGNITE_APPLICATION_BROKEN" % desired, timeout, from_the_beginning=True)

        try:
            self.await_event("IGNITE_APPLICATION_BROKEN", 1, from_the_beginning=True)
            raise IgniteExecutionException("Java application execution failed. %s" % self.extract_result("ERROR"))
        except TimeoutError:
            pass

        try:
            self.await_event(desired, 1, from_the_beginning=True)
        except Exception:
            raise Exception("Java application execution failed.") from None

    def clean_node(self, node):
        if self.alive(node):
            self.logger.warn("%s %s was still alive at cleanup time. Killing forcefully..." %
                             (self.__class__.__name__, node.account))

        node.account.kill_java_processes(self.servicejava_class_name, clean_shutdown=False, allow_fail=True)

        node.account.ssh("rm -rf %s" % self.PERSISTENT_ROOT, allow_fail=False)

    def pids(self, node):
        return node.account.java_pids(self.servicejava_class_name)

    def extract_result(self, name):
        """
        :param name: Result parameter's name.
        :return: Extracted result of application run.
        """
        results = self.extract_results(name)

        assert len(results) == len(self.nodes), f"Expected exactly {len(self.nodes)} occurence," \
                                                f" but found {len(results)}."

        return results[0] if results else ""

    def extract_results(self, name):
        """
        :param name: Results parameter's name.
        :return: Extracted results of application run.
        """
        res = []

        for node in self.nodes:
            output = node.account.ssh_capture(
                "grep '%s' %s" % (name + "->", self.STDOUT_STDERR_CAPTURE), allow_fail=False)
            for line in output:
                res.append(re.search("%s(.*)%s" % (name + "->", "<-"), line).group(1))

        return res
