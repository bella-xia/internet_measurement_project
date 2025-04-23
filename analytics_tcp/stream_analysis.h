#ifndef STREAM_ANALYSIS_H
#define STREAM_ANALYSIS_H

#include <unordered_map>
#include <iostream>
#include <vector>
#include <mutex>
#include <set>

#define SYN_BIT 0x02
#define ACK_BIT 0x10
#define RST_BIT 0x04
#define FIN_BIT 0x01

#define TLS_APPLICATION_DATA 0x17
#define TLS_HANDSHAKE 0x16
#define TLS_ALERT 0x15
#define TLS_CHANGE_CIPHER_SPEC 0x14

#define TLS_MAJOR_VER 0x03

#define TLS_MINOR_V0 0x01
#define TLS_MINOR_V1 0x02
#define TLS_MINOR_V2 0x03

enum handshake_status
{
    HANDSHAKE_INIT,
    HANDSHAKE_SYNED,
    HANDSHAKE_SYNACKED,
    HANDSHAKE_ACKED,
};

// used to store any intermediate data used to be able
// to later be incorporated into stream stats
struct workstation
{
    enum handshake_status status_handshake = HANDSHAKE_INIT;
    std::set<uint32_t> syn_ack_seqnums;
    std::unordered_map<std::string, std::unordered_map<uint32_t, std::tuple<uint64_t, uint32_t>>> packet_ts{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::set<uint32_t>> seqs_sent{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::vector<uint64_t>> rtts{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::vector<uint16_t>> wins{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, uint32_t> max_seqnums{{"src->dst", 0}, {"dst->src", 0}};
    bool tls_direction;

    uint64_t start_ts = 0;
    uint64_t end_ts = 0;

    uint64_t handshake_req = 0;
    uint64_t handshake_compl = 0;

    uint64_t tls_client_hello = 0;
    uint64_t tls_server_hello = 0;
};

struct stream_stats
{
    struct
    {
        std::string src_addr;
        std::string dst_addr;
        uint16_t sport;
        uint16_t dport;
    } identifier;

    // basic analytics
    struct
    {
        uint32_t src2dst_pkts = 0;
        uint32_t dst2src_pkts = 0;

        uint64_t src2dst_bytes = 0;
        uint64_t dst2src_bytes = 0;

        double duration = 0;
    } basics;

    // connection-level analysis
    struct flag_stats
    {
        uint32_t num_syn = 0;
        uint32_t num_ack = 0;
        uint32_t num_rst = 0;
        uint32_t num_fin = 0;
    } flags;

    // two-way handshake analysis
    struct handshake_stats
    {
        uint32_t syn_reqs = 0;
        uint32_t syn_acks = 0;
        uint32_t ack_affs = 0;

        double hanshake_duration = 0.0;
    } handshakes;

    // performances and throughputs
    struct throughput_stats
    {

        uint32_t avg_tput;     // Average throughput per stream
        uint32_t src2dst_tput; // Per-direction throughput
        uint32_t dst2src_tput;

        double rtt_avg; // average Round-Trip Time (RTT)
        double src2dst_rtt_avg;
        double dst2src_rtt_avg;

        double src2dst_rtt_std;
        double dst2src_rtt_std;

        uint16_t src2dst_win_avg;
        uint16_t dst2src_win_avg;
        uint16_t win_avg;
    } throughputs;

    // TLS-Specific Behavior
    struct tls_stats
    {
        int32_t num_raw_tcp = 0;
        int32_t num_tls = 0;
        std::set<int8_t> tls_ver;

        // TLS handshake
        double tls_handshake_duration;
    } tls;

    // Anomaly Detection & Traffic Characterization
    struct anormaly_stats
    {
        uint32_t num_retr = 0;   // Retransmission rate
        uint32_t num_o3 = 0;     // Out-of-order packets
        uint32_t num_dupack = 0; // Duplicate acknowledgements
    } anormalies;
};

void per_capture_tcp_stream(const std::string &file_path);

#endif // STREAM_ANALYSIS_H