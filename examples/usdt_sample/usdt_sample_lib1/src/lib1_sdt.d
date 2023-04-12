# This file is only relevant when using systemtap-sdt-devel (see usdt_sample.md).
#  This usdt_sample uses the StaticTracepoint.h header file (from folly) instead.
provider usdt_sample_lib1_sdt
{
    probe operation_start_sdt(uint64_t operation_id, const char* input);
    probe operation_end_sdt(uint64_t operation_id, const char* output);
};
