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

from distutils.version import LooseVersion

IgniteVersion = LooseVersion

DEV_VERSION = IgniteVersion("2.9.0-SNAPSHOT")

# 2.7.x versions
V_2_7_6 = IgniteVersion("2.7.6")
LATEST_2_7 = V_2_7_6

# 2.8.0 versions
V_2_8_0 = IgniteVersion("2.8.0")
V_2_8_1 = IgniteVersion("2.8.1")
LATEST_2_8 = V_2_8_1

LATEST_VERSION = LATEST_2_8
