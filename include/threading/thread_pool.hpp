#pragma once

#include "threading/block_queue.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

class ThreadPool {
 public:
  using Task = std::function<void()>;
  using ErrorHandler = std::function<void(std::string_view)>;

  explicit ThreadPool(size_t thread_count, ErrorHandler error_handler = {},
                      size_t queue_capacity = 0);
  ~ThreadPool() noexcept;

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;

  void Add(Task task);
  void Wait();
  void CancelPending();

 private:
  void WorkerLoop();

  BlockQueue<Task> tasks_;
  std::vector<std::thread> workers_;
  std::atomic<size_t> pending_tasks_{0};
  std::mutex wait_mutex_;
  std::condition_variable wait_cv_;
  ErrorHandler error_handler_;
};
