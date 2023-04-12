#include <linux/blkdev.h>
#include <uapi/linux/ptrace.h>

/**
 * @brief Helper method to filter based on the specified inputString.
 * @param inputString The operation input string to check against the filter.
 * @return True if the specified inputString starts with the hard-coded filter string; otherwise, false.
 */
static inline bool filter(char const* inputString)
{
    static const char* null_ptr = 0x0;
    static const char null_terminator = '\0';

    static const char filter_string[] = "FILTER_STRING"; ///< The filter string is replaced by python code.
    if (null_ptr == inputString) {
        return false;
    }

    // Compare until (not including) the null-terminator for filter_string
    for (int i = 0; i < sizeof(filter_string) - 1; ++i) {
        char c1 = *inputString++;
        if (null_terminator == c1) {
            return false;  // If the null-terminator for inputString was reached, it can not be equal to filter_string.
        }

        char c2 = filter_string[i];
        if (c1 != c2) {
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

    FILTER_STATEMENT ///< Replaced by python code.

    bpf_usdt_readarg(1, ctx, &start_data.operation_id);

    start_data.start = bpf_ktime_get_ns();
    start_hash.update(&start_data.operation_id, &start_data);
    return 0;
}
