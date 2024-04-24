#pragma once
#include <chrono>
#include <ctime>
#include <fstream>

#define LOG_PATH "local.log"

namespace local::log {

struct Log {
  public:
    static Log& getInstance() {
        static Log instance;
        return instance;
    }

    Log(Log const&) = delete;
    void operator=(Log const&) = delete;

    ~Log() { file_.close(); }

    template<typename... Args>
    void write(Args&&... args) {
        if (file_.is_open()) {
            (file_ << ... << std::forward<Args>(args));
        }
    }

  private:
    Log() { file_.open(LOG_PATH, std::ios::app); }
    std::ofstream file_;
};

template<typename... Args>
void write(Args&&... args) {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    Log::getInstance().write(std::ctime(&time));
    Log::getInstance().write(std::forward<Args>(args)..., '\n');
}

}  // namespace local::log
