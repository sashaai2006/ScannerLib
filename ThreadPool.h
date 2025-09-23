#pragma once

#ifndef DLL_EXPORT
#  ifdef _WIN32
#    define DLL_EXPORT __declspec(dllexport)
#  else
#    define DLL_EXPORT
#  endif
#endif

#include "BlockQueue.h"
#include <vector>
#include <thread>
#include <stdexcept>



template<typename Task>
class DLL_EXPORT ThreadPool {
private:
    BlockQueue<Task> tasks_;
    std::vector<std::thread> workers_;
    void worker_loop();
public:
    explicit ThreadPool(size_t count_thread);
    ~ThreadPool() noexcept;
    template<typename U>
    void Add(U&& task);
};

template<typename Task>
void ThreadPool<Task>::worker_loop() {
    while (true) {
        auto opt_task = tasks_.Get();
        if (!opt_task.has_value()) {
            break; 
        }
        try {
            (*opt_task)();
        } catch (...) {

        }
    }
}

template<typename Task>
ThreadPool<Task>::ThreadPool(size_t count_thread) {
    if (count_thread == 0) {
        throw std::invalid_argument("ThreadPool: thread_count > 0"); 
    }
    
    workers_.reserve(count_thread);
    
    try {
        for (std::size_t i = 0; i < count_thread; ++i) {
            workers_.emplace_back([this]() {
                worker_loop();
            });
        }
    } catch (...) {
        tasks_.Lock();
        for (auto& worker : workers_) {
            worker.join();
        }
        throw;
    }
}

template<typename Task>
ThreadPool<Task>::~ThreadPool() noexcept { 
    tasks_.Lock();
    for (auto& worker : workers_) {
        worker.join();
    }
}

template<typename Task>
template<typename U>
void ThreadPool<Task>::Add(U&& task) { 
  tasks_.Push(std::forward<U>(task));
}

