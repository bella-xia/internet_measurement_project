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
    std::unordered_map<std::string, std::unordered_map<uint32_t, std::tuple<uint64_t, bool>>> packet_ts{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::set<uint32_t>> seqs_sent{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, std::vector<uint32_t>> rtts{{"src->dst", {}}, {"dst->src", {}}};
    std::unordered_map<std::string, uint32_t> max_seqnums{{"src->dst", 0}, {"dst->src", 0}};
    bool tls_direction;
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

        uint64_t start_ts = 0;
        uint64_t end_ts = 0;
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
        /* UNUSED
         uint32_t rst_reqs = 0;
         uint32_t fin_reqs = 0;*/
        uint64_t handshake_req = 0;
        uint64_t handshake_compl = 0;
    } handshakes;

    // performances and throughputs
    struct throughput_stats
    {
        uint32_t avg_tput;     // Average throughput per stream
        uint32_t src2dst_tput; // Per-direction throughput
        uint32_t dst2src_tput;

        uint64_t avg_rrt; // average Round-Trip Time (RTT)
        uint64_t src2dst_rtt;
        uint64_t dst2src_rtt;
    } throughputs;

    // TLS-Specific Behavior
    struct tls_stats
    {
        int32_t num_raw_tcp = 0;
        int32_t num_tls = 0;
        std::set<int8_t> tls_ver;

        // TLS handshake
        uint64_t tls_client_hello = 0;
        uint64_t tls_server_hello = 0;

        /* UNUSED
        // Certificate Info
        std::string cert_domain;
        std::string cert_expiration;
        std::string cert_issuer;
        */
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