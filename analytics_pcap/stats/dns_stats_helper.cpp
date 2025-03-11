#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <pcap.h>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <cstring>
#include <cassert>
#include <netdb.h>

#include "../dns_main.h"

#define DNS_HEADER_SIZE 12

typedef struct
{
    uint16_t qtype;
    uint16_t qclass;
    std::string query_name;
} dns_query_t;

typedef struct
{
    uint16_t ans_type;
    uint16_t ans_class;
    uint32_t ttl;
    std::string response_data;
} dns_response_t;

typedef struct
{
    dns_query_t query;
    std::vector<dns_response_t> responses;
    time_t query_timestamp;
    time_t response_timestamp;
    bool responded = false;
} dns_data_t;

static void per_packet_helper(unsigned char *user_data, const struct pcap_pkthdr *header, const unsigned char *packet);
static void parse_dns_query(const u_char *dns_header, time_t packet_timestamp, std::unordered_map<std::string, dns_data_t> &dns_record);

void dns_record_analysis(const std::pair<std::string, std::string> &pcap_meta)
{
    const std::string pcap_path = pcap_meta.first, local_ip = pcap_meta.second;
    std::string start_dir = "../data/";
    size_t pos_start = pcap_path.find("../data/", 0);
    size_t pos_end = pcap_path.find(".pcap", 0);
    const std::string pcap_filename = pcap_path.substr(pos_start + start_dir.length(), pos_end - pos_start - start_dir.length());
    const std::string output_csv_dir = "data/dns_stats/" + pcap_filename + ".csv";
    std::cout << output_csv_dir << std::endl;
    char errbuf[256];

    pcap_t *handle = pcap_open_offline(pcap_path.c_str(), errbuf);
    std::unordered_map<std::string, dns_data_t> dns_query_record;

    if (handle == nullptr)
    {
        std::cerr << "Error opening pcap file " << pcap_path << ": " << errbuf << std::endl;
        return;
    }

    if (pcap_dispatch(handle, 0, per_packet_helper, reinterpret_cast<u_char *>(&dns_query_record)) < 0)
    {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << std::endl;
    }
    std::cout << dns_query_record.size() << std::endl;
    int num_responded = 0, num_missed = 0;
    for (auto it = dns_query_record.begin(); it != dns_query_record.end(); ++it)
    {
        // std::cout << "query domain name: " << it->first << std::endl;
        // std::cout << "dns response " << "[";
        // for (const dns_response_t &response : it->second.responses)
        //{
        //    std::cout << response.response_data << "; ";
        // }
        // std::cout << "]" << std::endl;
        if (it->second.responded)
            num_responded++;
        else
            num_missed++;
    }
    std::cout << "among the instances, " << num_responded << " are responded and " << num_missed << " are missed" << std::endl;

    std::ofstream output_csv(output_csv_dir);
    output_csv << "domain_name,query_ts,responded,response_ips,response_ts\n";

    for (const auto &entry : dns_query_record)
    {
        std::ostringstream oss;
        for (auto i : entry.second.responses)
        {
            oss << i.response_data << ";";
        }
        output_csv << entry.second.query.query_name << "," << entry.second.query_timestamp << ",";
        output_csv << entry.second.responded << "," << oss.str() << "," << entry.second.response_timestamp << std::endl;
    }
    output_csv.close();
    pcap_close(handle);
    return;
}

static void per_packet_helper(unsigned char *user_data,
                              const struct pcap_pkthdr *header,
                              const unsigned char *packet)
{
    auto *dns_query_record = reinterpret_cast<std::unordered_map<std::string, dns_data_t> *>(user_data);
    const struct ip *ip_header;
    // const struct udphdr *udp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    // uint16_t source_port, dest_port;
    time_t packet_timestamp = header->ts.tv_sec + 1000000 + header->ts.tv_usec;
    u_char *data;
    std::string data_str = "";

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    if (ip_header->ip_p == IPPROTO_UDP)
    {
        // DNS query should be UDP
        // udp_header = (udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        // source_port = ntohs(udp_header->source);
        // dest_port = ntohs(udp_header->dest);

        data = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        parse_dns_query(data, packet_timestamp, *dns_query_record);
    }

    static void parse_dns_query(const u_char *dns_header, time_t packet_timestamp,
                                std::unordered_map<std::string, dns_data_t> &dns_record)
    {
        uint16_t questions = ntohs(*(uint16_t *)(dns_header + 4));
        uint16_t answers = ntohs(*(uint16_t *)(dns_header + 6));

        const u_char *data_ptr = dns_header + DNS_HEADER_SIZE;

        // DNS is queried one at a time, so should not have multiple questions
        assert(questions <= 1);

        std::string domain_name;
        while (*data_ptr != 0)
        {
            int len = *data_ptr;
            data_ptr++;
            domain_name.append((char *)data_ptr, len);
            domain_name.append(".");
            data_ptr += len;
        }
        data_ptr++; // Skip the null byte

        uint16_t qtype = ntohs(*(uint16_t *)data_ptr);
        data_ptr += 2;
        uint16_t qclass = ntohs(*(uint16_t *)data_ptr);
        data_ptr += 2;
        if (qtype != 1)
        {
            // skip all non-A query for now
            return;
        }

        if (dns_record->find(domain_name) == dns_record->end())
        {
            assert(answers == 0); // If a name is not queried, it should not receive a response
            // std::cout << "inserted into domain name + port " << domain_name << " at timestamp " << packet_timestamp << std::endl;
            dns_data_t temp_data;
            temp_data.query_timestamp = packet_timestamp;
            temp_data.query = {qclass, qtype, domain_name};
            // std::cout << "responded to domain name + port " << domain_name << " at timestamp "
            dns_record->at(domain_name).response_timestamp = packet_timestamp;
            if (packet_timestamp <= dns_record->at(domain_name).query_timestamp)
            {
                std::cout << "Unexpected timestamp: queried at " << dns_record->at(domain_name).query_timestamp;
            }
        }

        for (int i = 0; i < answers; i++)
        {
            std::string answer_name;
            if (*data_ptr & 0xC0) // If it is a pointer
            {
                // int offset = (((*data_ptr) & 0x3F) << 8) | *(data_ptr + 1);
                data_ptr += 2; // Move past the pointer
            }
            else
            {
                while (*data_ptr != 0)
                {
                    int len = *(data_ptr++);
                    answer_name.append((char *)data_ptr, len);
                    answer_name.append(".");
                    data_ptr += len;
                }
                data_ptr++; // Skip the null byte
            }

            uint16_t ans_type = ntohs(*(uint16_t *)data_ptr);
            data_ptr += 2;
            uint16_t ans_class = ntohs(*(uint16_t *)data_ptr);
            data_ptr += 2;
            uint32_t ttl = ntohl(*(uint32_t *)data_ptr);
            data_ptr += 4;
            uint16_t data_length = ntohs(*(uint16_t *)data_ptr);
            data_ptr += 2;
            // std::cout << "ans type: " << ans_type << std::endl;

            std::string answer_data;
            if (ans_type == 1) // A record
            {
                char ip[INET_ADDRSTRLEN];
                struct in_addr addr;
                memcpy(&addr, data_ptr, sizeof(addr));
                inet_ntop(AF_INET, &addr, ip, sizeof(ip));
                answer_data = ip;
                dns_record->at(domain_name).responses.push_back({ans_type, ans_class, ttl, ip});
                if (!(dns_record->at(domain_name).responded))
                    dns_record->at(domain_name).responded = true;
            }
            else if (ans_type == 5)
            {
                std::cout << "... skip cname ... " << std::endl;
                // Ignore C name for now
                while (*data_ptr != 0) // CNAME record
                {                      // Read the CNAME (similar to domain name extraction)
                    int len = *(data_ptr++);
                    //     answer_data.append((char *)data_ptr, len);
                    //     answer_data.append(".");
                    data_ptr += len;
                }
                data_ptr++;
            }
            data_ptr += data_length;
        }
    }