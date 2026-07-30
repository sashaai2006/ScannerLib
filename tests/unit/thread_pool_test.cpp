#include "threading/thread_pool.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>

namespace {

TEST(ThreadPoolTest, ThrowsOnZeroThreads) {
    EXPECT_THROW(ThreadPool pool(0), std::invalid_argument);
}

TEST(ThreadPoolTest, ExecutesAllTasks) {
    constexpr int kTaskCount = 100;
    std::atomic<int> counter{0};

    {
        ThreadPool pool(4);
        for (int i = 0; i < kTaskCount; ++i) {
            pool.Add([&counter]() { counter.fetch_add(1); });
        }
        pool.Wait();
        EXPECT_EQ(counter.load(), kTaskCount);
    }
}

TEST(ThreadPoolTest, WaitReturnsImmediatelyWhenIdle) {
    ThreadPool pool(2);
    const auto start = std::chrono::steady_clock::now();
    pool.Wait();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 100);
}

TEST(ThreadPoolTest, DestructorCompletesRemainingTasks) {
    constexpr int kTaskCount = 50;
    std::atomic<int> counter{0};

    {
        ThreadPool pool(2);
        for (int i = 0; i < kTaskCount; ++i) {
            pool.Add([&counter]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                counter.fetch_add(1);
            });
        }
    }

    EXPECT_EQ(counter.load(), kTaskCount);
}

TEST(ThreadPoolTest, TasksRunInParallel) {
    constexpr int kTaskCount = 4;
    constexpr auto kSleep = std::chrono::milliseconds(150);

    ThreadPool pool(4);
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kTaskCount; ++i) {
        pool.Add([kSleep]() { std::this_thread::sleep_for(kSleep); });
    }
    pool.Wait();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),
              kTaskCount * kSleep.count());
}

TEST(ThreadPoolTest, ExceptionInTaskDoesNotKillWorker) {
    ThreadPool pool(1);
    std::atomic<bool> second_task_ran{false};

    pool.Add([]() { throw std::runtime_error("boom"); });
    pool.Add([&second_task_ran]() { second_task_ran = true; });
    pool.Wait();

    EXPECT_TRUE(second_task_ran.load());
}

TEST(ThreadPoolTest, ErrorHandlerReceivesTaskExceptions) {
    std::atomic<int> error_count{0};
    ThreadPool pool(1, [&error_count](std::string_view) {
        error_count.fetch_add(1);
    });

    pool.Add([]() { throw std::runtime_error("boom"); });
    pool.Wait();

    EXPECT_EQ(error_count.load(), 1);
}

TEST(ThreadPoolTest, PoolIsReusableAcrossWaits) {
    ThreadPool pool(2);
    std::atomic<int> counter{0};

    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 10; ++i) {
            pool.Add([&counter]() { counter.fetch_add(1); });
        }
        pool.Wait();
        EXPECT_EQ(counter.load(), (round + 1) * 10);
    }
}

} // namespace
