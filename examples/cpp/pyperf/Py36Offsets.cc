/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include "PyPerfType.h"

namespace ebpf {
namespace pyperf {

extern const OffsetConfig kPy36OffsetConfig = {
    .PyObject_type = 8,               // offsetof(PyObject, ob_type)
    .PyTypeObject_name = 24,          // offsetof(PyTypeObject, tp_name)
    .PyThreadState_frame = 24,        // offsetof(PyThreadState, frame)
    .PyThreadState_thread = 152,      // offsetof(PyThreadState, thread_id)
    .PyFrameObject_back = 24,         // offsetof(PyFrameObject, f_back)
    .PyFrameObject_code = 32,         // offsetof(PyFrameObject, f_code)
    .PyFrameObject_lineno = 124,      // offsetof(PyFrameObject, f_lineno)
    .PyFrameObject_localsplus = 376,  // offsetof(PyFrameObject, f_localsplus)
    .PyCodeObject_filename = 96,      // offsetof(PyCodeObject, co_filename)
    .PyCodeObject_name = 104,         // offsetof(PyCodeObject, co_name)
    .PyCodeObject_varnames = 64,      // offsetof(PyCodeObject, co_varnames)
    .PyTupleObject_item = 24,         // offsetof(PyTupleObject, ob_item)
    .String_data = 48,                // sizeof(PyASCIIObject)
    .String_size = 16,                // offsetof(PyVarObject, ob_size)
};

}
}  // namespace ebpf
