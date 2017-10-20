// std
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <queue>
#include <random>
#include <sstream>
#include <string>
#include <thread>

// gnu-c
#include <sys/types.h>
#include <unistd.h>

// usdt_sample_lib1
#include "usdt_sample_lib1/lib1.h"

void print_usage(int argc, char** argv)
{
    std::cout << "Usage:" << std::endl;
    std::cout << argv[0]
              << " <InputPrefix> <InputMinimum (1-50)> <InputMaximum (1-50)> <CallsPerSec (1-50)> <MinimumLatencyMs (1-50)> <MaximumLatencyMs (1-50)>"
              << std::endl;
    std::cout << "InputPrefix: Prefix of the input string to the operation. Default: dummy" << std::endl;
    std::cout << "InputMinimum: Minimum number to make the input string to the operation somewhat unique. Default: 1" << std::endl;
    std::cout << "InputMaximum: Maximum number to make the input string to the operation somewhat unique. Default: 50" << std::endl;
    std::cout << "CallsPerSec: Rate of calls to the operation. Default: 10" << std::endl;
    std::cout << "MinimumLatencyMs: Minimum latency to apply to the operation. Default: 20" << std::endl;
    std::cout << "MaximumLatencyMs: Maximum latency to apply to the operation. Default: 40" << std::endl;
}

int main(int argc, char** argv)
{
    std::string inputPrefix("dummy");
    std::uint32_t inputMinimum = 1;
    std::uint32_t inputMaximum = 50;
    std::uint32_t callsPerSec = 10;
    std::uint32_t minLatMs = 20;
    std::uint32_t maxLatMs = 40;

    try {
        if (argc > 1) {
            inputPrefix = argv[1];
        }

        if (argc > 2) {
            inputMinimum = static_cast<std::uint32_t>(std::max(1, std::min(50, std::atoi(argv[2]))));
        }

        if (argc > 3) {
            inputMaximum = static_cast<std::uint32_t>(std::max(1, std::min(50, std::atoi(argv[3]))));
        }

        if (argc > 4) {
            callsPerSec = static_cast<std::uint32_t>(std::max(1, std::min(50, std::atoi(argv[4]))));
        }

        if (argc > 5) {
            minLatMs = static_cast<std::uint32_t>(std::max(1, std::min(50, std::atoi(argv[5]))));
        }

        if (argc > 6) {
            maxLatMs = static_cast<std::uint32_t>(std::max(1, std::min(50, std::atoi(argv[6]))));
        }
    }
    catch (const std::exception& exc) {
        std::cout << "Exception while reading arguments: " << exc.what() << std::endl;
        print_usage(argc, argv);
        return -1;
    }
    catch (...) {
        std::cout << "Unknown exception while reading arguments." << std::endl;
        print_usage(argc, argv);
        return -1;
    }

    if (inputMinimum > inputMaximum) {
        std::cout << "InputMinimum must be smaller than InputMaximum." << std::endl;
        print_usage(argc, argv);
        return -1;
    }

    if (minLatMs > maxLatMs) {
        std::cout << "MinimumLatencyMs must be smaller than MaximumLatencyMs." << std::endl;
        print_usage(argc, argv);
        return -1;
    }

    std::cout << "Applying the following parameters:" << std::endl
              << "Input prefix: " << inputPrefix << "." << std::endl
              << "Input range: [" << inputMinimum << ", " << inputMaximum << "]." << std::endl
              << "Calls Per Second: " << callsPerSec << "." << std::endl
              << "Latency range: [" << minLatMs << ", " << maxLatMs << "] ms." << std::endl;

    const int sleepTimeMs = 1000 / callsPerSec;
    OperationProvider op(minLatMs, maxLatMs);

    std::mutex queueMutex;
    std::queue<std::shared_future<OperationResponse>> responseQueue;

    auto dequeueFuture = std::async(std::launch::async, [&]() {
        while (true) {
            bool empty = false;
            {
                std::lock_guard<std::mutex> lg(queueMutex);
                empty = responseQueue.empty();
            }

            if (empty) {
                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMs));
                continue;
            }

            responseQueue.front().get();

            // std::cout << "Removing item from queue." << std::endl;
            std::lock_guard<std::mutex> lg(queueMutex);
            responseQueue.pop();
        }
    });

    std::random_device rd;
    std::uniform_int_distribution<> dis(inputMinimum, inputMaximum);

    std::cout << "You can now run the bcc scripts, see usdt_sample.md for examples." << std::endl;
    std::cout << "pid: " << ::getpid() << std::endl;
    std::cout << "Press ctrl-c to exit." << std::endl;
    while (true) {
        std::ostringstream inputOss;
        inputOss << inputPrefix << "_" << dis(rd);
        auto responseFuture = op.executeAsync(OperationRequest(inputOss.str()));

        {
            std::lock_guard<std::mutex> lg(queueMutex);
            responseQueue.push(responseFuture);
        }

        // For a sample application, this is good enough to simulate callsPerSec.
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTimeMs));
    }

    dequeueFuture.get();
    return 0;
}
