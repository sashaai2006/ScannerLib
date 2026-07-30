#pragma once

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

template <typename T>
class BlockQueue {
 private:
  std::mutex mutex_;
  std::queue<T> queue_;
  std::condition_variable cv_;
  bool open_;

 public:
  BlockQueue() : open_(true) {}

  void Lock() {
    std::lock_guard lock(mutex_);
    open_ = false;
    cv_.notify_all();
  }

  bool Push(const T& val) {
    {
      std::lock_guard lock(mutex_);
      if (!open_) {
        return false;
      }
      queue_.push(val);
    }
    cv_.notify_one();
    return true;
  }

  bool Push(T&& val) {
    {
      std::lock_guard lock(mutex_);
      if (!open_) {
        return false;
      }
      queue_.push(std::move(val));
    }
    cv_.notify_one();
    return true;
  }

  std::optional<T> Get() {
    std::unique_lock lock(mutex_);
    cv_.wait(lock, [this] { return !queue_.empty() || !open_; });
    if (queue_.empty()) return std::nullopt;
    T val = std::move(queue_.front());
    queue_.pop();
    return val;
  }

  bool Empty() {
    std::lock_guard lock(mutex_);
    return queue_.empty();
  }

  size_t Size() {
    std::lock_guard lock(mutex_);
    return queue_.size();
  }
};
