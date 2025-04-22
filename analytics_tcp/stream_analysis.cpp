#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <fstream>
#include <tuple>
#include <iomanip>
#include <numeric>

#include "stream_analysis.h"

// #define PRINT
// #define DEBUG
#define ANALYTICS
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

#ifdef DEBUG
    std::ofstream outfile("log_file.txt");

    if (!outfile)
    {
        std::cerr << "Failed to open output.txt\n";
        return;
    }
#endif

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
#ifdef ANALYTICS
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
        uint64_t timestamp = static_cast<uint64_t>(header.ts.tv_sec) * 1000000UL + header.ts.tv_usec;

        if (!std::get<2>(stream_data))
            continue;

        bool direc = std::get<1>(stream_data);
        std::string d_ident = (direc) ? "src->dst" : "dst->src";
        std::string ackd_ident = (!direc) ? "src->dst" : "dst->src";
        std::string s_ident = std::get<0>(stream_data);

#ifdef DEBUG
        outfile << "Packet #" << packet_idx << std::endl;
        outfile << "getting tcp packet at " << timestamp << " microsecomd" << std::endl;
        outfile << "tcp stream: " << s_ident << std::endl;
#endif
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
        if (stream_ref.basics.start_ts == 0)
            stream_ref.basics.start_ts = timestamp;
        stream_ref.basics.end_ts = timestamp;

        // flags
        uint16_t p_flag = tcp_hdr->th_flags;
        stream_ref.flags.num_syn += ((p_flag & SYN_BIT) != 0);
        stream_ref.flags.num_ack += ((p_flag & ACK_BIT) != 0);
        stream_ref.flags.num_rst += ((p_flag & RST_BIT) != 0);
        stream_ref.flags.num_fin += ((p_flag & FIN_BIT) != 0);

#ifdef DEBUG
        outfile << (stream_ref.flags.num_syn ? "SYN " : "NO_SYN ");
        outfile << (stream_ref.flags.num_ack ? "ACK " : "NO_ACK ");
        outfile << (stream_ref.flags.num_rst ? "RST " : "NO_RST ");
        outfile << (stream_ref.flags.num_fin ? "FIN " : "NO_FIN ");
        outfile << std::endl;
#endif

        // handshake
        // condition for adding to syn_req: any syn packets??
        if ((p_flag & SYN_BIT) && !(p_flag & ACK_BIT))
        {
            stream_ref.handshakes.syn_reqs++;
            if (stream_ref.handshakes.handshake_req == 0)
                stream_ref.handshakes.handshake_req = timestamp;
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
            if (stream_ref.handshakes.handshake_compl == 0)
                stream_ref.handshakes.handshake_compl = timestamp;
        }

        // performances and throughputs & anomalies

        uint32_t seq_num = ntohl(tcp_hdr->seq);
        uint32_t ackseq_num = ntohl(tcp_hdr->ack_seq);
#ifdef DEBUG
        outfile << "found packet " << (std::get<1>(stream_data) ? "src->dst" : "dst->src") << " with sequence number " << seq_num << " and payload " << payload_len << std::endl;
#endif
        if (p_flag & ACK_BIT)
        {
            auto it = wkst_ref.packet_ts[ackd_ident].find(ackseq_num);
            if (it != wkst_ref.packet_ts[ackd_ident].end())
            {
                wkst_ref.rtts[ackd_ident].push_back(timestamp - std::get<0>(it->second));
#ifdef DEBUG
                outfile << d_ident << " acked packet sequence number " << ackseq_num << " with rtt " << timestamp - std::get<0>(it->second) << std::endl;
#endif
                if (!(p_flag & FIN_BIT) && std::get<1>(it->second)) // Dup ack
                {
                    stream_ref.anormalies.num_dupack++;
#ifdef DEBUG
                    outfile << "found duplicate acknowledgement on ack sequence number " << ackseq_num << std::endl;
#endif
                }
                else
                    wkst_ref.packet_ts[ackd_ident][ackseq_num] = {std::get<0>(it->second), true};
            }
            else
            {
#ifdef DEBUG
                outfile << "found an ack packet. but unable to find its corresponding prior packet: " << ackseq_num << std::endl;
#endif
            }
        }
        if (payload_len > 0)
        {
            auto it = wkst_ref.seqs_sent[d_ident].find(seq_num);
            bool ack_status = false;

            // retransmission
            if (it != wkst_ref.seqs_sent[d_ident].end())
            {
#ifdef DEBUG
                outfile << "found retransmitted packet with sequence number " << seq_num << std::endl;
#endif
                auto ts_record = wkst_ref.packet_ts[d_ident].find(seq_num + payload_len);
                ack_status = (ts_record != wkst_ref.packet_ts[d_ident].end()) ? std::get<1>(ts_record->second) : false;
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
                {
#ifdef DEBUG
                    outfile << "found out-of-order packet with sequence number " << seq_num << std::endl;
#endif
                    stream_ref.anormalies.num_o3++;
                }
            }
#ifdef DEBUG
            outfile << "inserting into packet ts sequence number " << seq_num + payload_len << std::endl;
#endif
            wkst_ref.packet_ts[d_ident][seq_num + payload_len] = {timestamp, ack_status};
            wkst_ref.seqs_sent[d_ident].insert(seq_num);
        }

#ifdef DEBUG
        outfile << "payload: ";
        if (payload_len > 10)
        {
            for (int i = 0; i < 10; i++)
                outfile << "0x" << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned>(static_cast<unsigned char>(payload[i]))) << std::dec << " ";
        }
        outfile << std::endl;
#endif

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
#ifdef DEBUG
                outfile << "identified TLS packet with version 1." << payload[2] - TLS_MINOR_V0 << std::endl;
#endif

                if (payload[0] == TLS_HANDSHAKE)
                {
                    if (stream_ref.tls.tls_client_hello == 0 && payload[5] == 0x01)
                    {
#ifdef DEBUG
                        outfile << "identified TLS handshake client hello" << std::endl;
#endif
                        stream_ref.tls.tls_client_hello = timestamp;
                    }
                    else if (stream_ref.tls.tls_server_hello == 0 && payload[5] == 0x02)
                    {
#ifdef DEBUG
                        outfile << "identified TLS handshake server hello" << std::endl;
#endif
                        stream_ref.tls.tls_server_hello = timestamp;
                    }
                }
            }
            else
                stream_ref.tls.num_raw_tcp++;
        }

#ifdef DEBUG
        outfile << std::endl;
#endif
        // if (packet_idx == 150)
        //     break;
#endif
    }
    pcap_close(handle);
#ifdef CSV
    unsigned last_idx = file_path.find_last_of("/");
    std::string csv_path = "data/" + file_path.substr(last_idx + 1) + ".csv";
    std::ofstream logFile(csv_path);

    // identifier
    logFile << "src_addr," << "dst_addr," << "sport," << "dport,";
    // basics
    logFile << "src2dst_pkts," << "dst2src_pkts," << "src2dst_bytes," << "dst2src_bytes," << "start_ts," << "end_ts,";
    // connection-lev analysis
    logFile << "num_syn," << "num_ack," << "num_rst," << "num_fin,";
    // handshake info
    logFile << "syn_reqs," << "syn_acks," << "ack_affs," << "handshake_req_ts," << "handshake_comp_ts,";
    // performances and throughputs
    logFile << "avg_tput," << "src2dst_tput," << "dst2src_tput," << "avg_rtt," << "src2dst_rtt," << "dst2src_rtt,";
    // tls
    logFile << "num_raw_tcp," << "num_tls," << "tls_vers," << "tls_client_hello_ts," << "tls_server_hello_ts,";
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
        logFile << stream_ins.basics.src2dst_pkts << "," << stream_ins.basics.dst2src_pkts << "," << stream_ins.basics.src2dst_bytes << "," << stream_ins.basics.dst2src_bytes << "," << stream_ins.basics.start_ts << "," << stream_ins.basics.end_ts << ",";

        // connection-lev analysis
        logFile << stream_ins.flags.num_syn << "," << stream_ins.flags.num_ack << "," << stream_ins.flags.num_rst << "," << stream_ins.flags.num_fin << ",";

        // handshake info
        logFile << stream_ins.handshakes.syn_reqs << "," << stream_ins.handshakes.syn_acks << "," << stream_ins.handshakes.ack_affs << "," << stream_ins.handshakes.handshake_req << "," << stream_ins.handshakes.handshake_compl << ",";

        // performances and throughputs
        ts_duration = stream_ins.basics.end_ts - stream_ins.basics.start_ts;
        avg_tput = static_cast<float>(stream_ins.basics.src2dst_bytes + stream_ins.basics.dst2src_bytes) / ts_duration;
        src2dst_tput = static_cast<float>(stream_ins.basics.src2dst_bytes) / ts_duration;
        dst2src_tput = static_cast<float>(stream_ins.basics.dst2src_bytes) / ts_duration;
        src2dst_rtt = std::accumulate(wkst_ins.rtts["src->dst"].begin(), wkst_ins.rtts["src->dst"].end(), 0);
        dst2src_rtt = std::accumulate(wkst_ins.rtts["dst->src"].begin(), wkst_ins.rtts["dst->src"].end(), 0);
        avg_rtt = static_cast<float>(src2dst_rtt + dst2src_rtt) / (wkst_ins.rtts["src->dst"].size() + wkst_ins.rtts["dst->src"].size());
        src2dst_rtt = static_cast<float>(src2dst_rtt) / wkst_ins.rtts["src->dst"].size();
        dst2src_rtt = static_cast<float>(dst2src_rtt) / wkst_ins.rtts["dst->src"].size();
        logFile << avg_rtt << "," << src2dst_tput << "," << dst2src_tput << "," << avg_rtt << "," << src2dst_rtt << "," << dst2src_rtt << ",";
        // tls
        logFile << stream_ins.tls.num_raw_tcp << "," << stream_ins.tls.num_tls << ",[";
        for (auto it = stream_ins.tls.tls_ver.begin(); it != stream_ins.tls.tls_ver.end(); ++it)
        {
            if (it != stream_ins.tls.tls_ver.begin())
                logFile << ";";               // or "," if you prefer
            logFile << static_cast<int>(*it); // convert int8_t to int to avoid weird characters
        }
        logFile << "],";
        logFile << stream_ins.tls.tls_client_hello << "," << stream_ins.tls.tls_server_hello << ",";
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
