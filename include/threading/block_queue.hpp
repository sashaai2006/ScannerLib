#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>

template <typename T>
class BlockQueue {
 private:
  std::mutex mutex_;
  std::queue<T> queue_;
  std::condition_variable not_empty_cv_;
  std::condition_variable not_full_cv_;
  size_t capacity_;
  bool open_;

  bool IsFullLocked() const {
    return capacity_ > 0 && queue_.size() >= capacity_;
  }

 public:
  explicit BlockQueue(size_t capacity = 0) : capacity_(capacity), open_(true) {}

  void Lock() {
    std::lock_guard lock(mutex_);
    open_ = false;
    not_empty_cv_.notify_all();
    not_full_cv_.notify_all();
  }

  size_t Clear() {
    std::lock_guard lock(mutex_);
    const size_t dropped = queue_.size();
    std::queue<T> empty;
    queue_.swap(empty);
    not_full_cv_.notify_all();
    return dropped;
  }

  bool Push(const T& val) {
    {
      std::unique_lock lock(mutex_);
      not_full_cv_.wait(lock, [this] { return !open_ || !IsFullLocked(); });
      if (!open_) {
        return false;
      }
      queue_.push(val);
    }
    not_empty_cv_.notify_one();
    return true;
  }

  bool Push(T&& val) {
    {
      std::unique_lock lock(mutex_);
      not_full_cv_.wait(lock, [this] { return !open_ || !IsFullLocked(); });
      if (!open_) {
        return false;
      }
      queue_.push(std::move(val));
    }
    not_empty_cv_.notify_one();
    return true;
  }

  std::optional<T> Get() {
    std::unique_lock lock(mutex_);
    not_empty_cv_.wait(lock, [this] { return !queue_.empty() || !open_; });
    if (queue_.empty()) {
      return std::nullopt;
    }
    T val = std::move(queue_.front());
    queue_.pop();
    not_full_cv_.notify_one();
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
