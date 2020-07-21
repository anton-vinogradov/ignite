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

FROM tiden-base:latest

ARG TIDEN_VERSION=latest

RUN \
    if [ "$TIDEN_VERSION" = "latest" ]; then \
        sudo -H pip3.7 \
            install \
                --no-cache-dir -q --extra-index-url https://pypi.org/simple/ --index-url https://test.pypi.org/simple/ \
                -U tiden; \
    else \
        sudo -H pip3.7 \
            install \
                --no-cache-dir -q --extra-index-url https://pypi.org/simple/ --index-url https://test.pypi.org/simple/ \
                tiden==${TIDEN_VERSION}; \
    fi
