#ifndef MAIN_H
#define MAIN_H

#include <string>

void extract_timestamp(const std::string &pcap_path);
void conversation_length_analysis(const std::pair<std::string, std::string> &pcap_meta);

#endif // MAIN_H