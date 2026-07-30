#include "threading/thread_pool.hpp"

#include <stdexcept>
#include <string>

ThreadPool::ThreadPool(size_t thread_count, ErrorHandler error_handler)
    : error_handler_(std::move(error_handler)) {
  if (thread_count == 0) {
    throw std::invalid_argument("ThreadPool: thread_count > 0");
  }

  workers_.reserve(thread_count);

  try {
    for (size_t i = 0; i < thread_count; ++i) {
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

ThreadPool::~ThreadPool() noexcept {
  tasks_.Lock();
  for (auto& worker : workers_) {
    worker.join();
  }
}

void ThreadPool::Add(Task task) {
  pending_tasks_.fetch_add(1);
  if (!tasks_.Push(std::move(task))) {
                                                                       
                                                            
    if (pending_tasks_.fetch_sub(1) == 1) {
      std::lock_guard<std::mutex> lock(wait_mutex_);
      wait_cv_.notify_all();
    }
    throw std::runtime_error(
        "ThreadPool: добавление задачи после остановки пула");
  }
}

void ThreadPool::Wait() {
  std::unique_lock<std::mutex> lock(wait_mutex_);
  wait_cv_.wait(lock, [this] { return pending_tasks_.load() == 0; });
}

void ThreadPool::WorkerLoop() {
  while (true) {
    auto opt_task = tasks_.Get();
    if (!opt_task.has_value()) {
      break;
    }
    try {
      (*opt_task)();
    } catch (const std::exception& e) {
      if (error_handler_) {
        error_handler_(std::string("Исключение в задаче пула потоков: ") +
                       e.what());
      }
    } catch (...) {
      if (error_handler_) {
        error_handler_("Неизвестное исключение в задаче пула потоков");
      }
    }
    if (pending_tasks_.fetch_sub(1) == 1) {
      std::lock_guard<std::mutex> lock(wait_mutex_);
      wait_cv_.notify_all();
    }
  }
}
