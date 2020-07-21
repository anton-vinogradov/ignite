#!/usr/bin/env python3
#
# Copyright 2017-2020 GridGain Systems.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from time import sleep, time
from tiden.apps.ignite import Ignite
from tiden.case.apptestcase import AppTestCase
from tiden.util import log_print
from apps.igniteaware import Igniteaware
from suites.version import IgniteVersion
from tiden.configuration_decorator import test_configuration


@test_configuration(['test_ignite_version'])
class TestRebalance(AppTestCase):

    NUM_NODES = 4
    PRELOAD_TIMEOUT = 60
    DATA_AMOUNT = 1000000
    REBALANCE_TIMEOUT = 60

    ignite: Ignite = property(lambda self: self.get_app('ignite'), None)
    ignite_artifact = property(lambda self: self.tiden.config['artifacts'][self.ignite.name], None)
    ignite_version: IgniteVersion = property(lambda self: IgniteVersion(self.tiden.config['test_ignite_version']), None)

    data_generation_client: Igniteaware = property(lambda self: self.get_app('data_generation'), None)

    def __init__(self, *args):
        super().__init__(*args)

        self.add_app(
            'ignite',
            artifact_name='ignite-' + str(self.ignite_version),
            num_nodes=self.NUM_NODES - 1
        )
        self.add_app(
            'data_generation',
            artifact_name='igniteaware',
            app_class_name='igniteaware',
            java_class_name="org.apache.ignite.internal.ducktest.DataGenerationApplication",
        )

    def setup(self):
        self.create_app_config_set(
            Ignite,
            addresses=self.ignite.get_hosts('server'),
            test_module_dir=self.ignite.remote_test_module_dir,
            additional_configs=['ignite-log4j.xml'],
        )
        super().setup()

    def test_add_node_rebalance(self):
        log_print(f"Ignite ver. {self.ignite_version}")

        self.ignite.set_node_option('*', 'config', Ignite.config_builder.get_config('server'))

        self.ignite.start_nodes()

        self.data_generation_client.run(
            self.ignite,
            params="test-cache,%d" % self.DATA_AMOUNT
        )

        node_idx = self.ignite.add_additional_nodes(Ignite.config_builder.get_config('server'), 1)
        self.ignite.start_additional_nodes(node_idx)
        self.ignite.wait_for_topology_snapshot(server_num=self.NUM_NODES)
        start = time()
        self.ignite.wait_message(
            "rebalanced=true, wasRebalanced=false",
            nodes_idx=node_idx,
            timeout=self.REBALANCE_TIMEOUT,
            interval=0.1,
        )
        data = {"Rebalanced in (sec)": time() - start}
        log_print(repr(data), color='green')
        self.ignite.stop_nodes(force=True)

    def teardown(self):
        super().teardown()

