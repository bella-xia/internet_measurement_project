#include <iostream>
#include <fstream>
#include <pcap.h>
#include <map>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <cstring>
#include <mutex>
#include <netdb.h>
#include "../main.h"
#include "../utils/utils.h"

typedef struct
{
    std::string ip_addr;     // server ip address
    std::string domain_name; // server domain name
    uint32_t packet_to;      // packets from the end host to server
    uint32_t packet_from;    // packets from the server to end host
    uint32_t byte_to;        // bytes from the end host to server
    uint32_t byte_from;      // bytes from the server to end host
} pcap_metadata_t;

typedef struct
{
    std::string local_ip;
    std::map<std::string, pcap_metadata_t> &conversations;
    unsigned char *user_data;
} packet_data_t;

const uint32_t threshold = 1000;
std::unordered_map<std::string, std::string> lookup_map;
std::mutex lookup_mutex;

static void per_packet_helper(unsigned char *user_data, const struct pcap_pkthdr *header, const unsigned char *packet,
                              const std::string local_ip, std::map<std::string, pcap_metadata_t> &conversations);

void conversation_length_analysis(const std::pair<std::string, std::string> &pcap_meta)
{
    const std::string pcap_path = pcap_meta.first, local_ip = pcap_meta.second;
    const std::string delimiter = "../data/pcap/";
    size_t pos = pcap_path.find(delimiter, 0);
    const std::string pcap_filename = (pos != std::string::npos) ? pcap_path.substr(pos + delimiter.length()) : pcap_path;
    const std::string output_csv_dir = "data/convbyte/" + pcap_filename + ".csv";
    char errbuf[256];

    pcap_t *handle = pcap_open_offline(pcap_path.c_str(), errbuf);

    if (handle == nullptr)
    {
        std::cerr << "Error opening pcap file " << pcap_path << ": " << errbuf << std::endl;
        return;
    }

    std::map<std::string, pcap_metadata_t> conversations = std::map<std::string, pcap_metadata_t>();
    packet_data_t data{local_ip, conversations, nullptr}; // Create the packet_data_t struct

    if (pcap_loop(handle, 0, [](unsigned char *user_data, const struct pcap_pkthdr *header, const unsigned char *packet)
                  {
            packet_data_t* data = reinterpret_cast<packet_data_t*>(user_data);
            per_packet_helper(data->user_data, header, packet, data->local_ip, data->conversations); }, reinterpret_cast<unsigned char *>(&data)) < 0)
    {
        std::cerr << "Error processing packets " << pcap_path << ": " << pcap_geterr(handle) << std::endl;
        return;
    }

    std::vector<pcap_metadata_t> sorted_conversations;

    // Filter conversations based on threshold and store them for sorting
    for (const auto &entry : conversations)
    {
        if (entry.second.byte_from >= threshold)
        {
            std::string src_domain = "";
            bool existing_result = false;
            {
                std::lock_guard<std::mutex> lock(lookup_mutex);
                std::unordered_map<std::string, std::string>::iterator lookup_result = lookup_map.find(entry.first);
                if (lookup_result != lookup_map.end())
                {
                    src_domain = lookup_result->second;
                    existing_result = true;
                }
            }

            // a. domain name unable to be resolved
            if (!existing_result)
            {
                src_domain = resolve_ip_to_hostname(entry.first);
                lookup_map[entry.first] = src_domain;
            }
            if (src_domain.length() == 0)
            {
                continue;
            }
            pcap_metadata_t temp_data = entry.second;
            temp_data.domain_name = src_domain;
            sorted_conversations.push_back(temp_data);
        }
    }

    // Sort the conversations by bytes transferred (in descending order)
    sort(sorted_conversations.begin(), sorted_conversations.end(),
         [](const pcap_metadata_t &a, const pcap_metadata_t &b)
         {
             return a.byte_from > b.byte_from;
         });

    std::ofstream output_csv(output_csv_dir);
    output_csv << "ip_addr,domain_name,packet_from,packet_to,byte_from,byte_to\n";

    for (const auto &entry : sorted_conversations)
    {
        output_csv << entry.ip_addr << "," << entry.domain_name << ",";
        output_csv << entry.packet_from << "," << entry.packet_to << ",";
        output_csv << entry.byte_from << "," << entry.byte_to << "\n";
    }
    output_csv.close();
    pcap_close(handle);
    return;
}
static void per_packet_helper(unsigned char *user_data,
                              const struct pcap_pkthdr *header,
                              const unsigned char *packet,
                              const std::string local_ip,
                              std::map<std::string, pcap_metadata_t> &conversations)
{
    struct ip *ip_header = (struct ip *)(packet + 14);

    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);

    // external server sending packets to end host
    if (is_private(dst_ip) && !is_private(src_ip))
    // std::strcmp(dst_ip.c_str(), local_ip.c_str()) == 0 && !is_private(src_ip))
    {
        auto result = conversations.emplace(src_ip, pcap_metadata_t{src_ip, "", 0, 1, 0, header->len});
        if (!result.second)
        {
            conversations[src_ip].byte_from += header->len;
            conversations[src_ip].packet_from += 1;
        }
    }

    // end host sending packets to external server
    else if (is_private(src_ip) && !is_private(dst_ip))
    // std::strcmp(src_ip.c_str(), local_ip.c_str()) == 0
    {
        auto result = conversations.emplace(dst_ip, pcap_metadata_t{dst_ip, "", 1, 0, header->len, 0});
        if (!result.second)
        {
            conversations[dst_ip].byte_to += header->len;
            conversations[dst_ip].packet_to += 1;
        }
    }
}