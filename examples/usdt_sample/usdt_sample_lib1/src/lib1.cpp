#include "usdt_sample_lib1/lib1.h"

// std
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

// usdt_sample_lib1
#include "folly/tracing/StaticTracepoint.h"

// When using systemtap-sdt-devel, the following file should be included:
// #include "usdt_sample_lib1/lib1_sdt.h"

OperationRequest::OperationRequest(const std::string& input_)
    : _input(input_)
{
}

OperationResponse::OperationResponse(const std::string& output_)
    : _output(output_)
{
}

OperationProvider::OperationProvider(std::uint32_t minLatencyMs_, std::uint32_t maxLatencyMs_)
    : _gen(std::random_device()())
    , _dis(minLatencyMs_, maxLatencyMs_)
{
}

std::shared_future<OperationResponse> OperationProvider::executeAsync(const OperationRequest& request)
{
    static std::atomic<std::uint64_t> operationIdCounter(0);
    std::uint64_t operationId = operationIdCounter++;

    FOLLY_SDT(usdt_sample_lib1, operation_start, operationId, request.input().c_str());

/* Below an example of how to use this sample with systemtap-sdt-devel:
    if (USDT_SAMPLE_LIB1_OPERATION_START_ENABLED()) {
        //std::cout << "operation_start probe enabled." << std::endl;
        USDT_SAMPLE_LIB1_OPERATION_START(operationId, &inputBuf);
    }
*/

    auto latencyMs = _dis(_gen);

    return std::async(std::launch::async, [latencyMs, operationId, request]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(latencyMs));

        auto output = std::string("resp_") + request.input();
        OperationResponse response(output);

        FOLLY_SDT(usdt_sample_lib1, operation_end, operationId, response.output().c_str());

/* Below an example of how to use this sample with systemtap-sdt-devel:
        if (USDT_SAMPLE_LIB1_OPERATION_END_ENABLED()) {
            //std::cout << "operation_end probe enabled." << std::endl;
            USDT_SAMPLE_LIB1_OPERATION_END(operationId, &outputBuf);
        }
*/

        return response;
    });
}
