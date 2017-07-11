#pragma once

// std
#include <cstdint>
#include <future>
#include <random>
#include <string>

/**
 * @brief Contains the operation request data.
 */
class OperationRequest
{
public:
    OperationRequest(const std::string& input);
    const std::string& input() const { return _input; }

private:
    std::string _input;
};

/**
 * @brief Contains the operation response data.
 */
class OperationResponse
{
public:
    OperationResponse(const std::string& output);
    const std::string& output() const { return _output; }

private:
    std::string _output;
};

/**
 * @brief Provides the operation.
 */
class OperationProvider
{
public:
    /**
     * @brief Constructs an instance of OperationProvider.
     * @param minLatencyMs The minimum latency to simulate for the operation.
     * @param maxLatencyMs The maximum latency to simulate for the operation.
     */
    OperationProvider(std::uint32_t minLatencyMs, std::uint32_t maxLatencyMs);

    /**
     * @brief Asynchronously executes the operation.
     * @param request The request input data for the operation.
     * @return A shared_future of the response of the operation.
     */
    std::shared_future<OperationResponse> executeAsync(const OperationRequest& request);

private:
    std::mt19937 _gen;                    ///< Used randomly determine an operation latency to simulate.
    std::uniform_int_distribution<> _dis; ///< Used randomly determine an operation latency to simulate.
};
