import json, os, statistics
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

if __name__ == '__main__':
    ROOT_DIR = 'analytics_dns/data'
    lev_bound = 0

    files = [file for file in os.listdir(ROOT_DIR) if file.endswith(".json")]
    ip_tested = [file.split('_')[2] for file in files]
    latency_dict_data = []
    mean_latencies, stdev_latencies, labels = [], [], []
    
    for file, ip_tested in zip(files, ip_tested):
        latency_counts = defaultdict(list)

        with open(os.path.join(ROOT_DIR, file), 'r') as f:
            json_data = json.load(f)
        
        total_idx = 0
        for dn, record in json_data.items():
            idx = 0
            tld_name = None
            
            lev_idx = 0
            for lev_name, aux_data in record.items():
                if "querytime" in aux_data:
                    if lev_bound <= lev_idx:
                        lev_bound = lev_idx + 1
                    latency_counts.setdefault(lev_idx, [])
                    latency_counts[lev_idx].append(aux_data["querytime"])
                    lev_idx += 1

        latency_dict_data.append((ip_tested, latency_counts.copy()))
   
    x = np.arange(lev_bound)
    labels = [f"lev {idx}" for idx in x]
    width = 0.15
    fig, ax = plt.subplots(figsize=(10, 8))
    
    for idx, (ip_tested, latency_instance) in enumerate(latency_dict_data):
        mean_latencies, stdev_latencies = [], []
        for i in x:
            mean_latencies.append(statistics.mean(latency_instance[i]) if len(latency_instance[i]) > 0 else 0)
            stdev_latencies.append(statistics.stdev(latency_instance[i]) if len(latency_instance[i]) > 1 else 0)
    
        ax.bar(x + (idx - 1) * width, mean_latencies, width, yerr=stdev_latencies, capsize=5)
    
    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Mean Latency (microseconds)')
    ax.set_title('Mean Latencies with Standard Deviation')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.axhline(0, color='grey', linewidth=0.8)
    # ax.set_ylim(0, max(mean_latencies) + max(stdev_latencies) * 1.1)  # Adjust y-axis limit
    ax.legend()
    
    plt.savefig("analytics_dns/images/dns_per_lev_stats.png")