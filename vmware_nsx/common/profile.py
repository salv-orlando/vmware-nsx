# Copyright 2019 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def profile(func):
    def wrap(*args, **kwargs):
        f_name = '{}.{}'.format(func.__module__, func.__name__)

        started_at = time.time()
        result = func(*args, **kwargs)
        LOG.debug(">>>>>>>>>>>>> Method %(method)s execution time %(time)f",
                  {'method': f_name, 'time': time.time() - started_at})
        return result

    return wrap
