import argparse
from parser import PingParser
import pandas as pd
import matplotlib.pyplot as plt

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--mode", type=str, default="ping")
    parser.add_argument("--trial", type=str, default="all")
    parser.add_argument("--hostname", type=str, default="172.24.45.125")
    parser.add_argument("--metadata_dir", type=str, default="../analytics_dframe/data/ip_geoloc_domain_mapping.csv")
    
    args = parser.parse_args()
    
    logger_dir = f"scamper_log/{args.trial}_{args.mode}_log.out"
    output_dir_01 = f"images/{args.trial}_{args.mode}_data_statistics_most_used.png"
    output_dir_02 = f"images/{args.trial}_{args.mode}_data_statistics_all.png"
    
    with open(logger_dir, 'r') as f:
        log = f.read()
    
    parser_module = PingParser if args.mode == "ping" else None
    ping_parser = parser_module(log, hostname=args.hostname)
    
    metadata_df = pd.read_csv(args.metadata_dir)
    unique_asns = metadata_df['asn_description'].unique()
    asn_dict = {}
    
    for unique_asn in unique_asns:
        filtered_df = metadata_df[metadata_df['asn_description'] == unique_asn].sort_values(by="total_byte_transferred", ascending=False)
        queriable_ips = filtered_df.iloc[:2]['ip_addr']
        ping_results = []
        
        for queriable_ip in queriable_ips:
            data_promise = ping_parser.find(queriable_ip)
            if len(data_promise) > 0:
                ping_results.append(data_promise)
        
        if len(ping_results) == 0:
            continue
        asn_dict[unique_asn] = ping_results
    
    # let's first do a graph on the first instance data
    total_asn_queried = len(asn_dict)
    most_used_min_data, most_used_mean_data, most_used_max_data, most_used_std_data = [], [], [], []
    all_min_data, all_mean_data, all_max_data, all_std_data = [], [], [], []
    available_asn, available_asn_plus_ip = [], []
    num_unreachable = [0] * len(asn_dict)
    for idx, (asn, specs) in enumerate(asn_dict.items()):
        flag = True
        
        for spec in specs:
            # print(f"{spec['queried ip']}, {asn}, {spec['packet loss rate']})")
            if spec['round-trip min']:
                all_min_data.append(spec['round-trip min'])
                all_mean_data.append(spec['round-trip mean'])
                all_max_data.append(spec['round-trip max'])
                all_std_data.append(spec['round-trip stddev'])
                asn_name = asn.split(" ")[0]
                asn_cc = asn.split(", ")[-1]
                asn_name = asn_name[:-1] if asn_name.endswith(",") else asn_name
                available_asn_plus_ip.append(f"{spec['queried ip']}({asn_name}, {asn_cc})")
                
                if flag:
                    most_used_min_data.append(spec['round-trip min'])
                    most_used_mean_data.append(spec['round-trip mean'])
                    most_used_max_data.append(spec['round-trip max'])
                    most_used_std_data.append(spec['round-trip stddev'])
                    asn_name = asn.split(" ")[0]
                    asn_cc = asn.split(", ")[-1]
                    asn_name = asn_name[:-1] if asn_name.endswith(",") else asn_name
                    available_asn.append(asn_name + ", " + asn_cc)
                    flag = False
            else:
                num_unreachable[idx] += 1
                
        fig, ax = plt.subplots(figsize=(18, 10))
        width = 0.2
        x_pos = range(len(available_asn))
        ax.bar([p - width for p in x_pos], most_used_min_data, width, label='min time', color='tab:blue')
        ax.bar([p for p in x_pos], most_used_mean_data, width, yerr=most_used_std_data, label='mean time', color='tab:orange')
        ax.bar([p + width for p in x_pos], most_used_max_data, width, label='max time', color='tab:green')
        
        ax.set_xticks(x_pos)
        ax.set_xticklabels(available_asn)
        ax.set_xlabel("ASN Description")
        ax.set_ylabel("Round-Trip Time (ms)")
        ax.legend()
        ax.set_title("Round-Trip Ping Statistics for Most Used IP Addresses")
        
        for i in range(len(available_asn)):
            ax.text(i - width, most_used_min_data[i] + 0.5, str(most_used_min_data[i]), ha='center', va='bottom')
            ax.text(i, most_used_mean_data[i] + 0.5, str(most_used_mean_data[i]), ha='center', va='bottom')
            ax.text(i + width, most_used_max_data[i] + 0.5, str(most_used_max_data[i]), ha='center', va='bottom')
            ax.text(i, most_used_mean_data[i] + most_used_std_data[i] + 1.5, f'±{most_used_std_data[i]}', 
                    ha='center', va='bottom', color='black')
        
        plt.tight_layout()
        plt.savefig(output_dir_01)
        
        fig, ax = plt.subplots(figsize=(20, 10))
        width = 0.2
        x_pos = range(len(available_asn_plus_ip))
        ax.bar([p - width for p in x_pos], all_min_data, width, label='min time', color='tab:blue')
        ax.bar([p for p in x_pos], all_mean_data, width, yerr=all_std_data, label='mean time', color='tab:orange')
        ax.bar([p + width for p in x_pos], all_max_data, width, label='max time', color='tab:green')
        
        ax.set_xticks(x_pos)
        ax.set_xticklabels(available_asn_plus_ip)
        ax.set_xlabel("ASN Description")
        ax.set_ylabel("Round-Trip Time (ms)")
        ax.legend()
        ax.set_title("Round-Trip Ping Statistics for IP Addresses")
        ax.tick_params(axis='x', labelrotation=15, labelsize=8)
        
        for i in range(len(available_asn_plus_ip)):
            ax.text(i - width, all_min_data[i] + 0.5, str(all_min_data[i]), ha='center', va='bottom')
            ax.text(i, all_mean_data[i] + 0.5, str(all_mean_data[i]), ha='center', va='bottom')
            ax.text(i + width, all_max_data[i] + 0.5, str(all_max_data[i]), ha='center', va='bottom')
            ax.text(i, all_mean_data[i] + all_std_data[i] + 1.5, f'±{all_std_data[i]}', ha='center', va='bottom', color='black')
        
        plt.tight_layout()
        plt.savefig(output_dir_02)