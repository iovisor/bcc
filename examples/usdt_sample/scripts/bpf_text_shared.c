#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

/**
 * @brief Helper method to filter based on the specified inputString.
 * @param inputString The operation input string to check against the filter.
 * @return True if the specified inputString starts with the hard-coded FILTER_STRING; otherwise, false.
 */
static inline bool filter(char const* inputString)
{
    char needle[] = "FILTER_STRING"; ///< The FILTER STRING is replaced by python code.
    char haystack[sizeof(needle)] = {};
    bpf_probe_read(&haystack, sizeof(haystack), (void*)inputString);
    for (int i = 0; i < sizeof(needle) - 1; ++i) {
        if (needle[i] != haystack[i]) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Contains the operation start data to trace.
 */
struct start_data_t
{
    u64 operation_id; ///< The id of the operation.
    char input[64];   ///< The input string of the request.
    u64 start;        ///< Timestamp of the start operation (start timestamp).
};

/**
 * @brief Contains the operation start data.
 * key: the operation id.
 * value: The operation start latency data.
 */
BPF_HASH(start_hash, u64, struct start_data_t);

/**
 * @brief Reads the operation request arguments and stores the start data in the hash.
 * @param ctx The BPF context.
 */
int trace_operation_start(struct pt_regs* ctx)
{
    struct start_data_t start_data = {};
    bpf_usdt_readarg_p(2, ctx, &start_data.input, sizeof(start_data.input));

    FILTER ///< Replaced by python code.

    bpf_usdt_readarg(1, ctx, &start_data.operation_id);

    start_data.start = bpf_ktime_get_ns();
    start_hash.update(&start_data.operation_id, &start_data);
    return 0;
}
