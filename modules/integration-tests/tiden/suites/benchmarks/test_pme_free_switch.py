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


from tiden.apps.ignite import Ignite
from tiden.case.apptestcase import AppTestCase
from tiden.util import log_print, util_sleep
from apps.igniteaware import Igniteaware
from suites.version import IgniteVersion
from tiden.configuration_decorator import test_configuration


@test_configuration(['test_ignite_version'])
class TestPmeFreeSwitch(AppTestCase):

    NUM_NODES = 3
    BATCH_SIZE = 1000
    NODE_LEAVE_TIMEOUT = 60
    TX_ALIVE_DURATION = 30

    ignite: Ignite = property(lambda self: self.get_app('ignite'), None)
    ignite_artifact = property(lambda self: self.tiden.config['artifacts'][self.ignite.name], None)
    ignite_version: IgniteVersion = property(lambda self: IgniteVersion(self.tiden.config['test_ignite_version']), None)

    long_tx_streamer: Igniteaware = property(lambda self: self.get_app('long_tx_streamer'), None)
    single_key_tx_streamer: Igniteaware = property(lambda self: self.get_app('single_key_tx_streamer'), None)

    def __init__(self, *args):
        super().__init__(*args)

        self.add_app(
            'ignite',
            artifact_name='ignite-' + str(self.ignite_version),
            num_nodes=self.NUM_NODES
        )
        self.add_app(
            'long_tx_streamer',
            name='LongTxStreamerApplication',
            artifact_name='igniteaware',
            app_class_name='igniteaware',
            java_class_name='org.apache.ignite.internal.ducktest.LongTxStreamerApplication',
        )
        self.add_app(
            'single_key_tx_streamer',
            name='SingleKeyTxStreamerApplication',
            artifact_name='igniteaware',
            app_class_name='igniteaware',
            java_class_name='org.apache.ignite.internal.ducktest.SingleKeyTxStreamerApplication',
        )

    def setup(self):
        self.create_app_config_set(
            Ignite,
            addresses=self.ignite.get_hosts('server'),
            test_module_dir=self.ignite.remote_test_module_dir,
            additional_configs=['ignite-log4j.xml'],
        )
        super().setup()

    def test_pme_latency(self):
        log_print(f"Ignite ver. {self.ignite_version}")
        data = {}
        self.ignite.set_node_option('*', 'config', Ignite.config_builder.get_config('server'))

        self.ignite.start_nodes()

        self.long_tx_streamer.start(
            self.ignite,
            params="test-cache"
        )

        self.single_key_tx_streamer.start(
            self.ignite,
            params="test-cache,%s" % self.BATCH_SIZE
        )

        if self.ignite.cu.is_baseline_autoajustment_supported():
            self.ignite.cu.disable_baseline_autoajustment()

        self.ignite.stop_nodes(2)

        self.long_tx_streamer.wait_message("Node left topology", timeout=self.NODE_LEAVE_TIMEOUT)

        util_sleep(self.TX_ALIVE_DURATION)

        self.long_tx_streamer.stop_nodes()

        self.single_key_tx_streamer.stop_nodes()

        data["Worst latency (ms)"] = self.single_key_tx_streamer.extract_result("WORST_LATENCY")
        data["Streamed txs"] = self.single_key_tx_streamer.extract_result("STREAMED")
        data["Measure duration (ms)"] = self.single_key_tx_streamer.extract_result("MEASURE_DURATION")

        log_print(repr(data), color='green')
        self.ignite.stop_nodes(force=True)

    def teardown(self):
        super().teardown()

