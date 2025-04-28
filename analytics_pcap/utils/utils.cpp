#include <iostream>
#include <arpa/inet.h>
#include <vector>
#include <future>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include "utils.h"

bool ends_with(const std::string &str, const std::string &suffix)
{
    if (str.length() < suffix.length())
    {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

bool is_private(const std::string &ip)
{
    std::mutex log_mutex;
    struct in_addr addr_v4;
    struct in6_addr addr_v6;
    if (inet_pton(AF_INET, ip.c_str(), &addr_v4) == 1)
    {
        uint32_t ip_int = ntohl(addr_v4.s_addr);
        return (ip_int >= 0x0A000000 && ip_int <= 0x0AFFFFFF) || // 10.0.0.0/8
               (ip_int >= 0xAC100000 && ip_int <= 0xAC1FFFFF) || // 172.16.0.0/12
               (ip_int >= 0xC0A80000 && ip_int <= 0xC0A8FFFF);   // 192.168.0.0/16
    }
    else if (inet_pton(AF_INET6, ip.c_str(), &addr_v6) != 1)
    {
        return (addr_v6.s6_addr[0] & 0xFE) == 0xFC ||
               (addr_v6.s6_addr[0] == 0xFE && (addr_v6.s6_addr[1] & 0xC0) == 0x80); // fe80::/10
    }
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cerr << "unable to parse currently ip address " << ip << std::endl;
    return false;
}

std::string resolve_ip_to_hostname(const std::string &ip)
{
    struct sockaddr_in sa;
    char host[1024];
    socklen_t len = sizeof(sa);

    // Convert the IP address to sockaddr_in
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    // Perform reverse DNS lookup using getnameinfo
    int result = getnameinfo((struct sockaddr *)&sa, len, host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (result == 0)
    {
        return std::string(host);
    }
    return "unresolved"; // Return empty if resolution fails
}