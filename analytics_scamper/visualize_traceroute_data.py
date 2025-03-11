import argparse, statistics
from parser import TraceRouteParser
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress

def is_private_or_invalid_ip(ip):
    if not ip:
        return True
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_private

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--mode", type=str, default="traceroute")
    parser.add_argument("--trial", type=str, default="cdn_cloud")
    parser.add_argument("--hostname", type=str, default="192.168.1.15")
    parser.add_argument("--metadata_dir", type=str, default="../analytics_dframe/data/ip_geoloc_domain_mapping.csv")
    
    args = parser.parse_args()
    
    logger_dir = f"./scamper_log/{args.trial}_{args.mode}_log.out"
    output_dir_01 = f"images/{args.trial}_{args.mode}_data_statistics_most_used.png" 
    output_dir_02 = f"images/{args.trial}_{args.mode}_data_statistics_all.png"
    
    with open(logger_dir, 'r') as f:
        log = f.read()
    
    parser_module = TraceRouteParser if args.mode == "traceroute" else None
    ping_parser = parser_module(log, hostname=args.hostname)
    
    metadata_df = pd.read_csv(args.metadata_dir)
    unique_asns = metadata_df['asn_description'].unique()
    asn_dict = {}
    
    for unique_asn in unique_asns:
        filtered_df = metadata_df[metadata_df['asn_description'] == unique_asn].sort_values(by="total_byte_transferred", ascending=False)
        queriable_ips = filtered_df.iloc[:5]['ip_addr']
        ping_results = []
        
        for queriable_ip in queriable_ips:
            data_promise = ping_parser.find(queriable_ip)
            if len(data_promise) > 0:
                print(f"asn {unique_asn} ip address {queriable_ip} has {len(data_promise)} instances of traceroute")
                ip_to_latency_dict = {}
                total_latency_count = []
                for hop_num in range(max([len(instance) for instance in data_promise])):
                    for instance in data_promise:
                        if hop_num < len(instance) and not is_private_or_invalid_ip(instance[hop_num][0]):
                            ip_hop = instance[hop_num]
                            total_latency_count.append(ip_hop[1])
                            ip_to_latency_dict[ip_hop[0]] = ip_to_latency_dict.get(ip_hop[0], []) + [ip_hop[1]]
                
                avg_latency_list = [statistics.mean(v) if len(v) > 1 else v[0] for v in ip_to_latency_dict.values()]
                stdev_latency_list = [statistics.stdev(v) if len(v) > 1 else 0 for v in ip_to_latency_dict.values()]
                ip_list = list(ip_to_latency_dict.keys())
                avg_total_latency, stdev_total_latency = statistics.mean(total_latency_count), statistics.stdev(total_latency_count)
                
                fig, ax = plt.subplots(figsize=(15, 10))
                width = 0.4
                x_pos = range(len(ip_list))
                ax.bar([p for p in x_pos], avg_latency_list, width, yerr=stdev_latency_list, color='tab:orange')
                
                x_limits = ax.get_xlim()

                ax.fill_between(x=(avg_total_latency - stdev_total_latency, 
                            avg_total_latency + stdev_total_latency), x1=x_limits[0], x2=x_limits[1], color='lightblue', alpha=0.5)
                
                ax.axhline(y=avg_total_latency, color='red', linestyle='--', linewidth=2, label='average total latency')
                ax.set_xticks(x_pos)
                ax.set_xticklabels(ip_list)
                ax.tick_params(axis='x', labelrotation=15, labelsize=8)
                ax.set_xlabel("IP Hop on Path")
                ax.set_ylabel("Latency (ms)")
                ax.legend()
                ax.set_title(f"Latency Measures Across Traceroute Path to IP {queriable_ip}, ANS {unique_asn}")
                
                for i in range(len(ip_list)):
                    ax.text(i, avg_latency_list[i] + 0.5, str(round(avg_latency_list[i], 2)), ha='center', va='bottom')
                    # ax.text(i, avg_latency_list[i] + stdev_latency_list[i] + 1.5, f'{round(stdev_latency_list[i], 2)}', ha='center', va='bottom', color='black')
                
                plt.tight_layout()
                plt.savefig(f"images/{queriable_ip}_{unique_asn}_traceroute_latency.png")