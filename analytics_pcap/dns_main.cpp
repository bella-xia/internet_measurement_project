#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <future>
#include "utils/utils.h"
#include "dns_main.h"

namespace fs = std::filesystem;

int main()
{
    std::string folder = "../data";
    std::vector<std::string> pcap_files;

    for (const auto &entry : fs::directory_iterator(folder))
    {
        if (entry.is_regular_file() && !entry.path().extension().empty())
            if (ends_with(entry.path().string(), "500.pcap"))
                pcap_files.push_back(entry.path().string());
    }

    for (int i = 0; i < pcap_files.size(); i++)
    {
        std::cout << "querying " << pcap_files[i] << std::endl;
        dns_record_analysis(std::make_pair(pcap_files[i], ""));
    }

    return 0;
    // std::vector<std::future<void>> futures;

    // for (const auto &file : pcap_files)
    // {
    //     futures.push_back(std::async(std::launch::async, dns_record_analysis, file));
    // }

    // for (auto &fut : futures)
    // {
    //     fut.get();
    // }
    // return 0;
}