import json, os, statistics
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

if __name__ == '__main__':
    ROOT_DIR = 'analytics_dns/data'
    id2tld, tld2id = {}, {}
    tld2counts = defaultdict(int)
    id_incrementals = 0

    files = [file for file in os.listdir(ROOT_DIR)  if file.endswith(".json")]
    ip_tested = [file.split('_')[2] for file in files]
    latency_dict_data = []
    mean_latencies, stdev_latencies, labels = [], [], []
    
    for file, ip_tested in zip(files, ip_tested):
        latency_counts = defaultdict(list)

        with open(os.path.join(ROOT_DIR, file), 'r') as f:
            json_data = json.load(f)
        
        total_idx = 0
        for dn, record in json_data.items():
            total_latency = 0
        
            tld_name = None
            if total_idx == 11:
                exit(0)
            for lev_name, aux_data in record.items():
                total_latency += aux_data.get("querytime", 0)
               
                tld_name = lev_name.split('.')[1]

                if tld_name not in tld2id:
                    tld2id[tld_name] = id_incrementals
                    id2tld[id_incrementals] = tld_name
                    id_incrementals += 1
                
                break

            
            if tld_name:
                latency_counts.setdefault(tld2id[tld_name], [])
                latency_counts[tld2id[tld_name]].append(total_latency)
                tld2counts[tld_name] += 1


        latency_dict_data.append((ip_tested, latency_counts.copy()))
    
    labels = [k for k, _ in tld2id.items() if tld2counts[k] > 5]
    idx_arr = [v for k, v in tld2id.items() if tld2counts[k] > 5]
    x = np.arange(len(labels))
    width = 0.15
    fig, ax = plt.subplots(figsize=(30, 12))


    for idx, (ip_tested, latency_instance) in enumerate(latency_dict_data):
        mean_latencies, stdev_latencies = [], []
        for i in idx_arr:
            mean_latencies.append(statistics.mean(latency_instance[i]) if len(latency_instance[i]) > 0 else 0)
            stdev_latencies.append(statistics.stdev(latency_instance[i]) if len(latency_instance[i]) > 1 else 0)
    
        ax.bar(x + (idx - 1) * width, mean_latencies, width, yerr=stdev_latencies, capsize=5, label=ip_tested)
    
    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Mean Latency (microseconds)')
    ax.set_title('Mean Latencies with Standard Deviation')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.axhline(0, color='grey', linewidth=0.8)
    ax.set_ylim(0, 500)  # Adjust y-axis limit
    ax.legend()
    
    plt.savefig("analytics_dns/images/dns_tld_stats.png")
    exit(0)
        

            


