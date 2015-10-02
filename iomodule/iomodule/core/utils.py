# Copyright 2015 PLUMgrid
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

import array

class BitArray(object):
    """Compact data structure to hold an array of bools
    """

    def __init__(self, capacity):
        self._data = array.array('L', (0 for i in range(0, capacity >> 5)))

    def __setitem__(self, index, value):
        slot = index >> 5
        offset = index & 0x1f
        old = self._data[slot]
        mask = ~(1 << offset) & 0xffffffff
        self._data[slot] = (old & mask) | (bool(value) << offset)

    def __getitem__(self, index):
        slot = index >> 5
        offset = index & 0x1f
        return bool((self._data[slot] >> offset) & 1)
