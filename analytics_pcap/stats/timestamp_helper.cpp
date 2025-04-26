#include <filesystem>
#include <fstream>
#include <iostream>
#include <fstream>
#include <vector>
#include <set>
// used for synchronization between threads
#include <mutex>
#include <thread>
#include <future>

#include "../main.h"

namespace fs = std::filesystem;
std::mutex log_mutex;

void extract_timestamp(const std::string &pcap_path)
{
    std::string command = "tshark -r " + pcap_path + " -T fields -e frame.time_epoch";
    std::set<double> timestamps;

    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Failed to run tshark on " << pcap_path << "\n";
        return;
    }

    char buffer[120];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        try
        {
            timestamps.insert(std::stod(buffer));
        }
        catch (const std::exception &e)
        {
            continue;
        }
    }
    pclose(pipe);

    if (!timestamps.empty())
    {
        int time_diff = static_cast<int>((*timestamps.rbegin() - *timestamps.begin()) / 60);
        std::lock_guard<std::mutex> lock(log_mutex); // used to restrict I/O
        std::ofstream log_file("logger.txt", std::ios::app);
        log_file << "The difference between first and last instance in "
                 << fs::path(pcap_path).filename().string()
                 << " is " << time_diff << " minutes\n";
        log_file.close();
    }
}