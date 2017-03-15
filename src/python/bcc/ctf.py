# Copyright (C) 2017 ShiftLeft Inc.
#
# Suchakrapani Sharma <suchakra@shiftleft.io>
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

import tempfile
from .utils import get_online_cpus


class DummyBabeltrace(object):
    def __init__(self, name):
        self.__name = name

    def __getattr__(self):
        raise ImportError("Babeltrace python bindings are not installed")

try:
    import babeltrace.writer as btw
    import babeltrace.common
except ImportError:
    btw = DummyBabeltrace(name='babeltrace.writer')
    babeltrace = DummyBabeltrace(name='babeltrace')


class CTFException(Exception):
    pass


class CTF(object):
    def __init__(self, event_name=None, path=None, fields=None):
        if path:
            self.path = path
        else:
            self.path = tempfile.mkdtemp()
        if event_name:
            self.event_name = event_name
        else:
            raise CTFException("Proper event name must be specified")

        if fields:
            self.fields = fields
        else:
            raise CTFException("Field names and types must be specified" )

        self.writer = btw.Writer(self.path)
        self.clock = btw.Clock('bcc')
        self.writer.add_clock(self.clock)
        self.event_class = btw.EventClass(self.event_name)
        self._init_fields()
        self.streams = self._get_streams()

    def _init_fields(self):
        if self.fields:
            for key, value in self.fields.items():
                self.event_class.add_field(value, key)
        else:
            raise CTFException("Payload field names and types must be specified")

    def _get_streams(self):
        streams = []
        sc = btw.StreamClass('bcc')
        sc.clock = self.clock
        sc.add_event_class(self.event_class)
        for i in get_online_cpus():
            s = self.writer.create_stream(sc)
            streams.insert(i, s)

        return streams

    class Type(object):
        u16 = btw.IntegerFieldDeclaration(16)
        u16.signed = False
        u32 = btw.IntegerFieldDeclaration(32)
        u32.signed = False
        u64 = btw.IntegerFieldDeclaration(64)
        u64.signed = False
        s16 = btw.IntegerFieldDeclaration(16)
        s16.signed = True
        s32 = btw.IntegerFieldDeclaration(32)
        s32.signed = True
        s64 = btw.IntegerFieldDeclaration(64)
        s64.signed = True
        string = btw.StringFieldDeclaration()
        string.encoding = babeltrace.common.CTFStringEncoding.UTF8


class CTFEvent(object):
    def __init__(self, ct):
        self.event = btw.Event(ct.event_class)

    def payload(self, field, value):
        self.event.payload(field).value = value

    def write(self, ct, cpu):
        ct.streams[cpu].append_event(self.event)
        ct.streams[cpu].flush()

    def time(self, ct, event_time):
        ct.clock.time = int(event_time)

