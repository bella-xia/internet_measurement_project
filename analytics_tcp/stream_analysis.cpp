#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <fstream>
#include <tuple>
#include <iomanip>
#include <numeric>
#include <cstring>
#include <cmath>

#include "stream_analysis.h"

#define CSV

std::mutex log_mutex;
static bool is_private_addr(uint32_t ip_addr);
static std::tuple<std::string, bool, bool> make_stream_key(const struct in_addr &ip1, uint16_t port1, const struct in_addr &ip2, uint16_t port2);

int packet_idx = 0;

void per_capture_tcp_stream(const std::string &file_path)
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(file_path.c_str(), errbuf);
    if (!handle)
    {
        std::cerr << "Couldn't open file: " << errbuf << "\n";
        return;
    }

    // data structure per capture
    std::vector<stream_stats> streams;
    std::vector<workstation> workstations;
    std::unordered_map<std::string, int> tuple2idx;
    uint32_t curr_idx = 0;

    const u_char *packet;
    struct pcap_pkthdr header;
    time_t firstTs, lastTs;
    firstTs = 0;
    bool started = false;
    int packet_idx = 0;

    while ((packet = pcap_next(handle, &header)) != nullptr)
    {
        packet_idx++;

        if (firstTs == 0)
            firstTs = header.ts.tv_sec;

        lastTs = header.ts.tv_sec;

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
            stream_stats new_stream;

            if (direc)
                new_stream.identifier = {std::string(inet_ntoa(ip_hdr->ip_src)), std::string(inet_ntoa(ip_hdr->ip_dst)),
                                         ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport)};
            else
                new_stream.identifier = {std::string(inet_ntoa(ip_hdr->ip_dst)), std::string(inet_ntoa(ip_hdr->ip_src)),
                                         ntohs(tcp_hdr->th_dport), ntohs(tcp_hdr->th_sport)};

            workstation new_workstation;
            streams.push_back(new_stream);
            workstations.push_back(new_workstation);
        }

        stream_stats &stream_ref = streams[stream_idx];
        workstation &wkst_ref = workstations[stream_idx];

        // basics
        if (direc)
        {
            stream_ref.basics.src2dst_pkts += 1;
            stream_ref.basics.src2dst_bytes += header.len;
        }
        else
        {
            stream_ref.basics.dst2src_pkts += 1;
            stream_ref.basics.dst2src_bytes += header.len;
        }
        if (wkst_ref.start_ts == 0.0)
            wkst_ref.start_ts = ts;
        wkst_ref.end_ts = ts;

        // flags
        uint16_t p_flag = tcp_hdr->th_flags;
        stream_ref.flags.num_syn += ((p_flag & SYN_BIT) != 0);
        stream_ref.flags.num_ack += ((p_flag & ACK_BIT) != 0);
        stream_ref.flags.num_rst += ((p_flag & RST_BIT) != 0);
        stream_ref.flags.num_fin += ((p_flag & FIN_BIT) != 0);

        // handshake
        // condition for adding to syn_req: any syn packets??
        if ((p_flag & SYN_BIT) && !(p_flag & ACK_BIT))
        {
            stream_ref.handshakes.syn_reqs++;
            if (wkst_ref.handshake_req == 0.0)
                wkst_ref.handshake_req = ts;
        }

        // condition for adding syn_ack: any syn + ack??
        if ((p_flag & SYN_BIT) && (p_flag & ACK_BIT))
        {
            stream_ref.handshakes.syn_acks++;
            wkst_ref.syn_ack_seqnums.insert(tcp_hdr->seq + 1);
        }

        // conditon for adding to ack_aff: any ack that has a sequence number
        // that is originally in the syn ack?
        if ((p_flag & ACK_BIT) &&
            wkst_ref.syn_ack_seqnums.find(tcp_hdr->ack_seq) != wkst_ref.syn_ack_seqnums.end())
        {
            stream_ref.handshakes.ack_affs++;
            if (wkst_ref.handshake_compl == 0.0)
                wkst_ref.handshake_compl = ts;
        }

        // performances and throughputs & anomalies
        uint32_t seq_num = ntohl(tcp_hdr->seq);
        uint32_t ackseq_num = ntohl(tcp_hdr->ack_seq);
        if (p_flag & ACK_BIT)
        {
            auto it = wkst_ref.packet_ts[ackd_ident].find(ackseq_num);
            if (it != wkst_ref.packet_ts[ackd_ident].end())
            {
                if (!(p_flag & FIN_BIT) && std::get<1>(it->second) == seq_num) // Dup ack
                    stream_ref.anormalies.num_dupack++;
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
                stream_ref.anormalies.num_retr++;
            }
            else
            {
                /* since packets are processed in chronilogical order
                any packetwith sequence number smaller than the current max seqnum
                 while not being a re-transmission is considered out-of-order */
                if (seq_num >= wkst_ref.max_seqnums[d_ident])
                    wkst_ref.max_seqnums[d_ident] = seq_num;
                else
                    stream_ref.anormalies.num_o3++;
            }

            wkst_ref.packet_ts[d_ident][seq_num + payload_len] = {ts, ack_status};
            wkst_ref.seqs_sent[d_ident].insert(seq_num);
        }

        /*  check for likely TLS traffic:
             Byte 0: Content Type (0x16 for Handshake)
             Byte 1-2: TLS Version (e.g., 0x03 0x03 for TLS 1.2)
             Byte 3-4: Length of payload */

        if (payload_len > 0)
        {
            // check for tls fingerprints
            if ((payload[0] >= TLS_CHANGE_CIPHER_SPEC && payload[0] <= TLS_APPLICATION_DATA) && payload[1] == TLS_MAJOR_VER && (payload[2] >= TLS_MINOR_V0 && payload[2] <= TLS_MINOR_V2))
            {
                stream_ref.tls.num_tls++;
                stream_ref.tls.tls_ver.insert(payload[2] - TLS_MINOR_V0);

                if (payload[0] == TLS_HANDSHAKE)
                {
                    if (wkst_ref.tls_client_hello == 0 && payload[5] == 0x01)
                        wkst_ref.tls_client_hello = ts;

                    else if (wkst_ref.tls_server_hello == 0 && payload[5] == 0x02)
                        wkst_ref.tls_server_hello = ts;
                }
            }
            else
                stream_ref.tls.num_raw_tcp++;
        }

        uint64_t src2dst_rtt, dst2src_rtt, variance;

        for (unsigned ins_idx = 0; ins_idx < tuple2idx.size(); ins_idx++)
        {

            struct stream_stats &stream_ins = streams[ins_idx];
            struct workstation &wkst_ins = workstations[ins_idx];

            // basics
            stream_ins.basics.duration = static_cast<double>(wkst_ins.end_ts - wkst_ins.start_ts) / 1e6;

            // handshake
            if (wkst_ins.handshake_req != 0 && wkst_ins.handshake_compl != 0)
                stream_ins.handshakes.hanshake_duration = static_cast<double>(wkst_ins.handshake_compl - wkst_ins.handshake_req) / 1e6;

            // performacne & throughput
            stream_ins.throughputs.avg_tput = static_cast<double>(stream_ins.basics.src2dst_bytes + stream_ins.basics.dst2src_bytes) / stream_ins.basics.duration;
            stream_ins.throughputs.src2dst_tput = static_cast<double>(stream_ins.basics.src2dst_bytes) / stream_ins.basics.duration;
            stream_ins.throughputs.dst2src_tput = static_cast<double>(stream_ins.basics.dst2src_bytes) / stream_ins.basics.duration;
            src2dst_rtt = std::accumulate(wkst_ins.rtts["src->dst"].begin(), wkst_ins.rtts["src->dst"].end(), 0ULL);
            dst2src_rtt = std::accumulate(wkst_ins.rtts["dst->src"].begin(), wkst_ins.rtts["dst->src"].end(), 0ULL);
            stream_ins.throughputs.rtt_avg = (wkst_ins.rtts["src->dst"].size() + wkst_ins.rtts["dst->src"].size()) ? static_cast<double>(src2dst_rtt + dst2src_rtt) / (wkst_ins.rtts["src->dst"].size() + wkst_ins.rtts["dst->src"].size()) : 0;
            stream_ins.throughputs.src2dst_rtt_avg = (wkst_ins.rtts["src->dst"].size()) ? static_cast<double>(src2dst_rtt) / wkst_ins.rtts["src->dst"].size() : 0;
            stream_ins.throughputs.dst2src_rtt_avg = (wkst_ins.rtts["dst->src"].size()) ? static_cast<double>(dst2src_rtt) / wkst_ins.rtts["dst->src"].size() : 0;

            variance = 0;
            if (wkst_ins.rtts["src->dst"].size() > 1)
            {
                for (const auto &rtt : wkst_ins.rtts["src->dst"])
                    variance += (rtt - static_cast<uint64_t>(stream_ins.throughputs.src2dst_rtt_avg)) * (rtt - static_cast<uint64_t>(stream_ins.throughputs.src2dst_rtt_avg));

                variance /= wkst_ins.rtts["src->dst"].size();
            }
            stream_ins.throughputs.src2dst_rtt_std = static_cast<double>(std::sqrt(variance)) / 1e6;

            variance = 0;
            if (wkst_ins.rtts["dst->src"].size() > 1)
            {
                for (const auto &rtt : wkst_ins.rtts["dst->src"])
                    variance += (rtt - static_cast<uint64_t>(stream_ins.throughputs.dst2src_rtt_avg)) * (rtt - static_cast<uint64_t>(stream_ins.throughputs.dst2src_rtt_avg));

                variance /= wkst_ins.rtts["dst->src"].size();
            }
            stream_ins.throughputs.dst2src_rtt_std = static_cast<double>(std::sqrt(variance)) / 1e6;
            stream_ins.throughputs.rtt_avg /= 1e6;
            stream_ins.throughputs.src2dst_rtt_avg /= 1e6;
            stream_ins.throughputs.dst2src_rtt_avg /= 1e6;

            // tls
            if (wkst_ins.tls_client_hello != 0 && wkst_ins.tls_server_hello != 0)
                stream_ins.tls.tls_handshake_duration = static_cast<double>(wkst_ins.tls_server_hello - wkst_ins.tls_client_hello) / 1e6;
        }
    }
    pcap_close(handle);
#ifdef CSV
    unsigned last_idx = file_path.find_last_of("/");
    std::string csv_path = "data/" + file_path.substr(last_idx + 1) + ".csv";
    std::ofstream logFile(csv_path);

    // identifier
    logFile << "src_addr," << "dst_addr," << "sport," << "dport,";
    // basics
    logFile << "src2dst_pkts," << "dst2src_pkts," << "src2dst_bytes," << "dst2src_bytes," << "duration,";
    // connection-lev analysis
    logFile << "num_syn," << "num_ack," << "num_rst," << "num_fin,";
    // handshake info
    logFile << "syn_reqs," << "syn_acks," << "ack_affs," << "handshake_duration,";
    // performances and throughputs
    logFile << "avg_tput," << "src2dst_tput," << "dst2src_tput," << "rtt_avg," << "src2dst_rtt_avg," << "dst2src_rtt_avg," << "src2dst_rtt_std," << "dst2src_rtt_std,";
    // tls
    logFile << "num_raw_tcp," << "num_tls," << "tls_vers," << "tls_handshake_duration,";
    // anomaly
    logFile << "num_retransmission," << "num_outoforder," << "num_duplicate_ack" << "\n";

    uint64_t avg_tput,
        src2dst_tput, dst2src_tput;
    uint64_t avg_rtt, src2dst_rtt, dst2src_rtt;
    uint64_t ts_duration;

    for (unsigned ins_idx = 0; ins_idx < tuple2idx.size(); ins_idx++)
    {
        struct stream_stats &stream_ins = streams[ins_idx];
        struct workstation &wkst_ins = workstations[ins_idx];

        // identifier
        logFile << stream_ins.identifier.src_addr << "," << stream_ins.identifier.dst_addr << "," << stream_ins.identifier.sport << "," << stream_ins.identifier.dport << ",";

        // basics
        logFile << stream_ins.basics.src2dst_pkts << "," << stream_ins.basics.dst2src_pkts << "," << stream_ins.basics.src2dst_bytes << "," << stream_ins.basics.dst2src_bytes << "," << stream_ins.basics.duration << ",";

        // connection-lev analysis
        logFile << stream_ins.flags.num_syn << "," << stream_ins.flags.num_ack << "," << stream_ins.flags.num_rst << "," << stream_ins.flags.num_fin << ",";

        // handshake info
        logFile << stream_ins.handshakes.syn_reqs << "," << stream_ins.handshakes.syn_acks << "," << stream_ins.handshakes.ack_affs << "," << stream_ins.handshakes.hanshake_duration << ",";

        // performance
        logFile << stream_ins.throughputs.avg_tput << "," << stream_ins.throughputs.src2dst_tput << "," << stream_ins.throughputs.dst2src_tput << ",";
        logFile << stream_ins.throughputs.rtt_avg << "," << stream_ins.throughputs.src2dst_rtt_avg << "," << stream_ins.throughputs.dst2src_rtt_avg << "," << stream_ins.throughputs.src2dst_rtt_std << "," << stream_ins.throughputs.dst2src_rtt_std << ",";

        // tls
        logFile << stream_ins.tls.num_raw_tcp << "," << stream_ins.tls.num_tls << ",[";
        for (auto it = stream_ins.tls.tls_ver.begin(); it != stream_ins.tls.tls_ver.end(); ++it)
        {
            if (it != stream_ins.tls.tls_ver.begin())
                logFile << ";";               // or "," if you prefer
            logFile << static_cast<int>(*it); // convert int8_t to int to avoid weird characters
        }
        logFile << "],";
        logFile << stream_ins.tls.tls_handshake_duration << ",";
        // anomaly
        logFile << stream_ins.anormalies.num_retr << "," << stream_ins.anormalies.num_o3 << "," << stream_ins.anormalies.num_dupack << "\n";
    }
    logFile.close();
#endif
#ifdef PRINT
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << "_________ navigating " << file_path << " _________" << std::endl;
    std::cout << "Total capture duration: " << (lastTs - firstTs) << " seconds" << std::endl;
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
