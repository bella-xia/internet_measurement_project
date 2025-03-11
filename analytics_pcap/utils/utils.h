#ifndef UTILS_H
#define UTILS_H

#include <string>

bool end_with(const std::string &str, const std::string &suffix);
bool is_private(const std::string &ip);
std::string resolve_ip_to_hostname(const std::string &ip);

#endif // UTILS_H
