import os, statistics
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

if __name__ == "__main__":
    data_dir = "../analytics_pcap/data/dns_stats"
    dates = os.listdir(data_dir)
    print(dates)
    mean_latencies = []
    stdev_latencies = []
    
    for data in dates:
        df = pd.read_csv(os.path.join(data_dir, data), sep=",")
        df = df[df['responded'] == True]
        print(len(df))
        df['latency'] = df.apply(lambda x : x['response_ts'] - x['query_ts'], axis=1)
        print(df[df['latency'] < 0])
        mean_latencies.append(statistics.mean(df['latency']))
        stdev_latencies.append(statistics.stdev(df['latency']))
    
    print(mean_latencies, stdev_latencies)
    
    x = np.arange(len(mean_latencies))  # the label locations
    width = 0.35  # the width of the bars
    
    fig, ax = plt.subplots()
    bars = ax.bar(x, mean_latencies, width, yerr=stdev_latencies, capsize=5)
    
    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Mean Latency (microseconds)')
    ax.set_title('Mean Latencies with Standard Deviation')
    ax.set_xticks(x)
    ax.set_xticklabels(["Cloudfare [1.0.0.1]", "default", "Google [8.8.4.1]"])
    ax.axhline(0, color='grey', linewidth=0.8)
    ax.set_ylim(0, max(mean_latencies) + max(stdev_latencies) * 1.1)  # Adjust y-axis limit
    
    plt.savefig("images/dns_stats_trial2.png")