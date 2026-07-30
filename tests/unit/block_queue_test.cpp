#include "threading/block_queue.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace {

TEST(BlockQueueTest, FifoOrderSingleThread) {
    BlockQueue<int> queue;
    queue.Push(1);
    queue.Push(2);
    queue.Push(3);

    EXPECT_EQ(queue.Get(), 1);
    EXPECT_EQ(queue.Get(), 2);
    EXPECT_EQ(queue.Get(), 3);
}

TEST(BlockQueueTest, GetReturnsNulloptAfterLockWhenEmpty) {
    BlockQueue<int> queue;
    queue.Lock();
    EXPECT_FALSE(queue.Get().has_value());
}

TEST(BlockQueueTest, LockWakesUpWaitingConsumers) {
    BlockQueue<int> queue;
    std::atomic<bool> consumer_finished{false};

    std::thread consumer([&]() {
        const auto value = queue.Get();
        EXPECT_FALSE(value.has_value());
        consumer_finished = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(consumer_finished.load());

    queue.Lock();
    consumer.join();
    EXPECT_TRUE(consumer_finished.load());
}

TEST(BlockQueueTest, PushMoveOnlyType) {
    BlockQueue<std::unique_ptr<int>> queue;
    auto ptr = std::make_unique<int>(42);
    queue.Push(std::move(ptr));
    EXPECT_EQ(ptr, nullptr);

    const auto result = queue.Get();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(**result, 42);
}

TEST(BlockQueueTest, MultiProducerMultiConsumer) {
    constexpr int kProducers = 4;
    constexpr int kConsumers = 4;
    constexpr int kItemsPerProducer = 250;
    constexpr int kTotalItems = kProducers * kItemsPerProducer;

    BlockQueue<int> queue;
    std::atomic<int> consumed_count{0};
    std::atomic<long> consumed_sum{0};

    std::vector<std::thread> consumers;
    for (int c = 0; c < kConsumers; ++c) {
        consumers.emplace_back([&]() {
            while (const auto value = queue.Get()) {
                consumed_sum.fetch_add(*value);
                consumed_count.fetch_add(1);
            }
        });
    }

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&queue, p]() {
            for (int i = 1; i <= kItemsPerProducer; ++i) {
                queue.Push(p * kItemsPerProducer + i);
            }
        });
    }

    for (auto& producer : producers) {
        producer.join();
    }
    queue.Lock();
    for (auto& consumer : consumers) {
        consumer.join();
    }

    EXPECT_EQ(consumed_count.load(), kTotalItems);

    long expected_sum = 0;
    for (int p = 0; p < kProducers; ++p) {
        for (int i = 1; i <= kItemsPerProducer; ++i) {
            expected_sum += p * kItemsPerProducer + i;
        }
    }
    EXPECT_EQ(consumed_sum.load(), expected_sum);
}

TEST(BlockQueueTest, PushAfterLockIsDropped) {
    BlockQueue<int> queue;
    EXPECT_TRUE(queue.Push(1));
    queue.Lock();
    EXPECT_FALSE(queue.Push(2));

    EXPECT_EQ(queue.Get(), 1);
    EXPECT_FALSE(queue.Get().has_value());
}

}            
