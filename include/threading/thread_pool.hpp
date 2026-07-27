#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "threading/block_queue.hpp"
#include "utils/logger.hpp"

template <typename Task>
class ThreadPool {
 private:
  BlockQueue<Task> tasks_;
  std::vector<std::thread> workers_;
  std::atomic<size_t> pending_tasks_{0};
  std::mutex wait_mutex_;
  std::condition_variable wait_cv_;
  void WorkerLoop();

 public:
  explicit ThreadPool(size_t count_thread);
  ~ThreadPool() noexcept;
  template <typename U>
  void Add(U&& task);
  void Wait();
};

template <typename Task>
void ThreadPool<Task>::WorkerLoop() {
  while (true) {
    auto opt_task = tasks_.Get();
    if (!opt_task.has_value()) {
      break;
    }
    try {
      (*opt_task)();
    } catch (const std::exception& e) {
      Logger::Instance().Error(
          std::string("Исключение в задаче пула потоков: ") + e.what());
    } catch (...) {
      Logger::Instance().Error("Неизвестное исключение в задаче пула потоков");
    }
    if (pending_tasks_.fetch_sub(1) == 1) {
      std::lock_guard<std::mutex> lock(wait_mutex_);
      wait_cv_.notify_all();
    }
  }
}

template <typename Task>
ThreadPool<Task>::ThreadPool(size_t count_thread) {
  if (count_thread == 0) {
    throw std::invalid_argument("ThreadPool: thread_count > 0");
  }

  workers_.reserve(count_thread);

  try {
    for (std::size_t i = 0; i < count_thread; ++i) {
      workers_.emplace_back([this]() { WorkerLoop(); });
    }
  } catch (...) {
    tasks_.Lock();
    for (auto& worker : workers_) {
      worker.join();
    }
    throw;
  }
}

template <typename Task>
ThreadPool<Task>::~ThreadPool() noexcept {
  tasks_.Lock();
  for (auto& worker : workers_) {
    worker.join();
  }
}

template <typename Task>
template <typename U>
void ThreadPool<Task>::Add(U&& task) {
  pending_tasks_.fetch_add(1);
  tasks_.Push(std::forward<U>(task));
}

template <typename Task>
void ThreadPool<Task>::Wait() {
  std::unique_lock<std::mutex> lock(wait_mutex_);
  wait_cv_.wait(lock, [this] { return pending_tasks_.load() == 0; });
}
