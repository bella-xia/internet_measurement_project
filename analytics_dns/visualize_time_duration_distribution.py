import json, os, statistics
import numpy as np
import matplotlib.pyplot as plt

if __name__ == '__main__':
    ROOT_DIR = 'analytics_dns/data'

    files = [file for file in os.listdir(ROOT_DIR)  if file.endswith(".json")]
    ip_tested = [file.split('_')[2] for file in files]
    
    files = [file for file in os.listdir(ROOT_DIR)  if file.endswith(".json")]
    ip_tested = [file.split('_')[2] for file in files]
    mean_latencies, stdev_latencies, labels = [], [], []
    
    for file, ip_tested in zip(files, ip_tested):
        latency_counts = []

        with open(os.path.join(ROOT_DIR, file), 'r') as f:
            json_data = json.load(f)
        
        idx = 0
        for dn, record in json_data.items():
            total_latency = 0
            for lev_name, aux_data in record.items():
                total_latency += aux_data.get("querytime", 0)
            
            latency_counts.append(total_latency)
        
        labels.append(ip_tested)
        mean_latencies.append(statistics.mean(latency_counts))
        stdev_latencies.append(statistics.stdev(latency_counts))
    
    x = np.arange(len(mean_latencies))  # the label locations
    width = 0.35  # the width of the bars
    
    fig, ax = plt.subplots()
    bars = ax.bar(x, mean_latencies, width, yerr=stdev_latencies, capsize=5)
    
    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Mean Latency (microseconds)')
    ax.set_title('Mean Latencies with Standard Deviation')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.axhline(0, color='grey', linewidth=0.8)
    ax.set_ylim(0, max(mean_latencies) + max(stdev_latencies) * 1.1)  # Adjust y-axis limit
    
    plt.savefig("analytics_dns/images/dns_overall_stats.png")
        

            


