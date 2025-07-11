#include <thread>
#include <iostream>
#include <vector>
#include <filesystem>
#include <iostream>
#include "stream_analysis.h"
#include "anomaly_analysis.h"

#define MULTI_THREAD
// #define STREAM
#define ANOMALY
#define MAX_THREADS 20

namespace fs = std::filesystem;

int main(int argc, char *argv[])
{
    std::string root_dir = (argc > 1) ? argv[1] : "../data/pcap";

#ifdef MULTI_THREAD
    std::vector<std::thread> threads;

    for (const auto &entry : fs::directory_iterator(root_dir))
    {
#ifdef STREAM
        threads.emplace_back(per_capture_tcp_stream, entry.path().string());
#endif
#ifdef ANOMALY
        threads.emplace_back(per_capture_tcp_anomaly, entry.path().string());
#endif
    }

    for (auto &t : threads)
        t.join();
#else
    for (const auto &entry : fs::directory_iterator(root_dir))
    {
        per_capture_tcp_stream(entry.path().string());
        // std::cout << "checking file entry " << entry.path().string() << std::endl;
        break;
    }
#endif
    return 0;
}
