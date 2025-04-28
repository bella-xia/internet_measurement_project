#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <fstream>
#include <tuple>
#include <mutex>
#include <iomanip>
#include <numeric>
#include <cstring>
#include "anomaly_analysis.h"

#define CSV

std::mutex log_mutex;
static bool is_private_addr(uint32_t ip_addr);
static std::tuple<std::string, bool, bool> make_stream_key(const struct in_addr &ip1, uint16_t port1, const struct in_addr &ip2, uint16_t port2);

int packet_idx = 0;

void per_capture_tcp_anomaly(const std::string &file_path)
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(file_path.c_str(), errbuf);
    if (!handle)
    {
        std::cerr << "Couldn't open file: " << errbuf << "\n";
        return;
    }

    std::vector<anomaly_stats> anomalies;
    std::vector<struct anomaly_workstation> workstations;
    std::unordered_map<std::string, int> tuple2idx;
    uint32_t curr_idx = 0;

    const u_char *packet;
    struct pcap_pkthdr header;
    time_t firstTs, lastTs, starter_ts;
    firstTs = 0;
    bool started = false;
    int packet_idx = 0;

    while ((packet = pcap_next(handle, &header)) != nullptr)
    {
        packet_idx++;

        const struct ether_header *eth = (struct ether_header *)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            continue;
        const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_hdr->ip_p != IPPROTO_TCP)
            continue;

        int ip_hdr_len = ip_hdr->ip_hl * 4;
        const struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

        // tls behavior
        int tcp_hdr_len = tcp_hdr->th_off * 4;
        const u_char *payload = packet + sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;
        unsigned short payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;

        auto stream_data = make_stream_key(ip_hdr->ip_src, ntohs(tcp_hdr->th_sport),
                                           ip_hdr->ip_dst, ntohs(tcp_hdr->th_dport));
        uint64_t ts = header.ts.tv_sec * 1e6 + header.ts.tv_usec;
        if (firstTs == 0)
        {
            firstTs = header.ts.tv_sec;
            starter_ts = ts;
            ts = 0;
        }
        else
        {
            ts = ts - starter_ts;
            lastTs = header.ts.tv_sec;
        }

        if (!std::get<2>(stream_data))
            continue;

        bool direc = std::get<1>(stream_data);
        std::string d_ident = (direc) ? "src->dst" : "dst->src";
        std::string ackd_ident = (!direc) ? "src->dst" : "dst->src";
        std::string s_ident = std::get<0>(stream_data);

        auto [it, inserted] = tuple2idx.emplace(s_ident, curr_idx);
        uint32_t stream_idx = it->second;
        if (inserted)
        {
            curr_idx++;
            // create new instance and add identifiers
            anomaly_stats new_stream;

            if (direc)
                new_stream.identifier = {std::string(inet_ntoa(ip_hdr->ip_src)), std::string(inet_ntoa(ip_hdr->ip_dst)),
                                         ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport)};
            else
                new_stream.identifier = {std::string(inet_ntoa(ip_hdr->ip_dst)), std::string(inet_ntoa(ip_hdr->ip_src)),
                                         ntohs(tcp_hdr->th_dport), ntohs(tcp_hdr->th_sport)};

            struct anomaly_workstation new_workstation;
            anomalies.push_back(new_stream);
            workstations.push_back(new_workstation);
        }

        struct anomaly_stats &stream_ref = anomalies[stream_idx];
        struct anomaly_workstation &wkst_ref = workstations[stream_idx];

        // basics

        if (stream_ref.basics.start_ts == 0)
            stream_ref.basics.start_ts = ts;
        stream_ref.basics.end_ts = ts;

        // performances and throughputs & anomalies]
        uint16_t p_flag = tcp_hdr->th_flags;
        uint32_t seq_num = ntohl(tcp_hdr->seq);
        uint32_t ackseq_num = ntohl(tcp_hdr->ack_seq);
        wkst_ref.wins[d_ident].push_back(ntohs(tcp_hdr->window));
        if (p_flag & ACK_BIT)
        {
            auto it = wkst_ref.packet_ts[ackd_ident].find(ackseq_num);
            if (it != wkst_ref.packet_ts[ackd_ident].end())
            {
                if (!(p_flag & FIN_BIT) && std::get<1>(it->second) == seq_num)
                {
                    stream_ref.anomaly_num.num_dupack++;
                    stream_ref.anomaly_ts.dupack_packet_ts.push_back(ts);
                }
                else
                {
                    wkst_ref.packet_ts[ackd_ident][ackseq_num] = {std::get<0>(it->second), seq_num};
                    wkst_ref.rtts[ackd_ident].push_back(ts - std::get<0>(it->second));
                }
            }
        }
        if (payload_len > 0)
        {
            auto it = wkst_ref.seqs_sent[d_ident].find(seq_num);
            uint32_t ack_status = false;

            // retransmission
            if (it != wkst_ref.seqs_sent[d_ident].end())
            {
                auto ts_record = wkst_ref.packet_ts[d_ident].find(seq_num + payload_len);
                ack_status = (ts_record != wkst_ref.packet_ts[d_ident].end()) ? std::get<1>(ts_record->second) : seq_num;
                stream_ref.anomaly_num.num_retr++;
                stream_ref.anomaly_ts.retr_packet_ts.push_back(ts);
            }
            else
            {
                /* since packets are processed in chronilogical order
                any packetwith sequence number smaller than the current max seqnum
                 while not being a re-transmission is considered out-of-order */
                if (seq_num >= wkst_ref.max_seqnums[d_ident])
                    wkst_ref.max_seqnums[d_ident] = seq_num;
                else
                {
                    stream_ref.anomaly_num.num_o3++;
                    stream_ref.anomaly_ts.o3_packet_ts.push_back(ts);
                }
            }

            wkst_ref.packet_ts[d_ident][seq_num + payload_len] = {ts, ack_status};
            wkst_ref.seqs_sent[d_ident].insert(seq_num);
        }
    }
    pcap_close(handle);
#ifdef CSV
    unsigned last_idx = file_path.find_last_of("/");
    std::string csv_path = "data/" + file_path.substr(last_idx + 1) + "_anomaly.csv";
    std::ofstream logFile(csv_path);

    // identifier
    logFile << "src_addr," << "dst_addr," << "sport," << "dport,";
    // basics
    logFile << "start_ts," << "end_ts,";
    // anomaly numbers
    logFile << "num_retransmission," << "num_outoforder," << "num_duplicate_ack,";
    // anomaly stats
    logFile << "ts_retransmission," << "ts_outoforder," << "ts_duplicate_ack\n";

    for (unsigned ins_idx = 0; ins_idx < tuple2idx.size(); ins_idx++)
    {
        struct anomaly_stats &stream_ins = anomalies[ins_idx];
        struct anomaly_workstation &wkst_ins = workstations[ins_idx];

        // identifier
        logFile << stream_ins.identifier.src_addr << "," << stream_ins.identifier.dst_addr << "," << stream_ins.identifier.sport << "," << stream_ins.identifier.dport << ",";

        // basics
        logFile << static_cast<double>(stream_ins.basics.start_ts) / 1e6 << "," << static_cast<double>(stream_ins.basics.end_ts) / 1e6 << ",";

        // anomaly
        logFile << stream_ins.anomaly_num.num_retr << "," << stream_ins.anomaly_num.num_o3 << "," << stream_ins.anomaly_num.num_dupack << ",";

        logFile << "[";
        for (auto it = stream_ins.anomaly_ts.retr_packet_ts.begin(); it != stream_ins.anomaly_ts.retr_packet_ts.end(); ++it)
        {
            if (it != stream_ins.anomaly_ts.retr_packet_ts.begin())
                logFile << ";";
            logFile << static_cast<double>(*it) / 1e6;
        }
        logFile << "],";

        logFile << "[";
        for (auto it = stream_ins.anomaly_ts.o3_packet_ts.begin(); it != stream_ins.anomaly_ts.o3_packet_ts.end(); ++it)
        {
            if (it != stream_ins.anomaly_ts.o3_packet_ts.begin())
                logFile << ";";
            logFile << static_cast<double>(*it) / 1e6;
        }
        logFile << "],";

        logFile << "[";
        for (auto it = stream_ins.anomaly_ts.dupack_packet_ts.begin(); it != stream_ins.anomaly_ts.dupack_packet_ts.end(); ++it)
        {
            if (it != stream_ins.anomaly_ts.dupack_packet_ts.begin())
                logFile << ";";
            logFile << static_cast<double>(*it) / 1e6;
        }
        logFile << "]\n";
    }
    logFile.close();
#endif
}

static std::tuple<std::string, bool, bool> make_stream_key(const struct in_addr &ip1, uint16_t port1, const struct in_addr &ip2, uint16_t port2)
{
    uint32_t ipaddr_1 = ip1.s_addr;
    uint32_t ipaddr_2 = ip2.s_addr;
    bool ispri_1 = is_private_addr(ip1.s_addr);
    bool ispri_2 = is_private_addr(ip2.s_addr);

    // both are private or both are public. invalid. exiting
    if ((ispri_1 && ispri_2) || ((!ispri_1) && (!ispri_2)))
        return {"", false, false};

    std::string ipstr_1 = std::string(inet_ntoa(ip1));
    std::string ipstr_2 = std::string(inet_ntoa(ip2));

    if (ispri_1)
        return {ipstr_1 + ":" + std::to_string(port1) + "-" + ipstr_2 + ":" + std::to_string(port2), true, true};

    return {ipstr_2 + ":" + std::to_string(port2) + "-" + ipstr_1 + ":" + std::to_string(port1), false, true};
}

static bool is_private_addr(uint32_t ip_addr)
{
    ip_addr = ntohl(ip_addr); // convert to host order if needed

    return ((ip_addr >= 0x0A000000 && ip_addr <= 0x0AFFFFFF) ||
            (ip_addr >= 0xAC100000 && ip_addr <= 0xAC1FFFFF) ||
            (ip_addr >= 0xC0A80000 && ip_addr <= 0xC0A8FFFF));
}
