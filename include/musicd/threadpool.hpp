#pragma once

#include <thread>
#include <vector>

class ThreadPool {

public:
  ThreadPool() {}
  ThreadPool(int n_workers, std::function<void()> worker_fun) {
    _workers.reserve(n_workers);
    for (int i = 0; i < n_workers; i++) {
      _workers.emplace_back(worker_fun);
    }
  }
  ~ThreadPool() {
    for (auto &thread : _workers) {
      thread.join();
    }
  }

private:
  std::vector<std::thread> _workers;
};
