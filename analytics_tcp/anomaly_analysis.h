#ifndef ANOMALY_ANALYSIS_H
#define ANOMALY_ANALYSIS_H

#include <set>
#include <unordered_map>
#include <iostream>
#include <vector>

#define ACK_BIT 0x10
#define FIN_BIT 0x01

struct anomaly_workstation
{
    std::set<uint32_t> syn_ack_seqnums;
    std::unordered_map<std::string, std::unordered_map<uint32_t, std::tuple<uint64_t, uint32_t>>> packet_ts{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::set<uint32_t>> seqs_sent{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::vector<uint64_t>> rtts{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::vector<uint16_t>> wins{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, uint32_t> max_seqnums{{"src->dst", 0}, {"dst->src", 0}};
};

struct anomaly_stats
{
    struct
    {
        std::string src_addr;
        std::string dst_addr;
        uint16_t sport;
        uint16_t dport;
    } identifier;

    struct
    {
        double start_ts = 0;
        double end_ts = 0;
    } basics;

    struct anormaly_numeric
    {
        uint32_t num_retr = 0;
        uint32_t num_o3 = 0;
        uint32_t num_dupack = 0;
    } anomaly_num;

    struct anormaly_timestamps
    {
        std::vector<uint64_t> o3_packet_ts{};
        std::vector<uint64_t> retr_packet_ts{};
        std::vector<uint64_t> dupack_packet_ts{};
    } anomaly_ts;
};

void per_capture_tcp_anomaly(const std::string &file_path);
#endif