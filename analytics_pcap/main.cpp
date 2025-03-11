// main.cpp
#include "main.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <future>

namespace fs = std::filesystem;

void get_local_ip_config(std::map<std::string, std::string> &local_host_config)
{
    std::string config_csv = "config/local_ip_config.csv";
    std::ifstream file(config_csv);

    if (!file.is_open())
    {
        std::cerr << "Failed to open file " << config_csv << std::endl;
    }

    std::string line;

    while (std::getline(file, line))
    {
        std::stringstream ss(line);
        std::string file_name, local_host;
        std::getline(ss, file_name, ',');
        std::getline(ss, local_host, ',');
        local_host_config[file_name] = local_host;
    }
}

int main()
{
    std::map<std::string, std::string> local_host_config{};
    get_local_ip_config(local_host_config);

    std::string folder = "../data";
    std::vector<std::pair<std::string, std::string>> pcap_files;

    for (const auto &entry : fs::directory_iterator(folder))
    {
        if (entry.is_regular_file() && entry.path().extension().empty())
        {
            pcap_files.push_back(std::make_pair(entry.path().string(), local_host_config[entry.path().string().substr(folder.length() + 1)]));
        }
    }

    std::vector<std::future<void>> futures;

    for (const auto &file : pcap_files)
    {
        futures.push_back(std::async(std::launch::async, conversation_length_analysis, file));
    }

    for (auto &fut : futures)
    {
        fut.get();
    }

    return 0;
}