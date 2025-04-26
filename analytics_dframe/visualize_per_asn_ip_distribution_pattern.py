import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

if __name__ == "__main__":
    df_dir = "data/ip_geoloc_domain_mapping.csv"
    df = pd.read_csv(df_dir)
    
    # heatmap visualization
    heatmap_df = df[['asn_description', 'asn_cidr', 'total_byte_transferred', 'total_packet_transferred']]
    aggregated_data = heatmap_df.groupby(['asn_description', 'asn_cidr'], as_index=False).sum()
    
    aggregated_data['asn_cidr_sort_key'] = aggregated_data['asn_cidr'].apply(lambda x : tuple((
                int(x.split('/')[0].split('.')[i]) 
                for i in range(4)))
            )
    expected_asn_cidr_order = aggregated_data.sort_values(by='asn_cidr_sort_key')['asn_cidr']
    heatmap_data = aggregated_data.pivot(index='asn_description', columns='asn_cidr', values='total_packet_transferred')
    heatmap_data = heatmap_data.reindex(columns=expected_asn_cidr_order)
    
    plt.figure(figsize=(20, 10))
    log_heatmap_data = np.log10(heatmap_data.replace(0, np.nan))
    sns.heatmap(log_heatmap_data, annot=False, cmap="viridis")
    plt.title("Total Packets Transferred per ASN and IP Prefix [Log 10 Scale]")
    plt.xticks(rotation=45)
    plt.yticks(rotation=30)
    plt.grid()
    plt.savefig("images/log_heatmap_ordered_by_packet.png")
    
    heatmap_data = aggregated_data.pivot(index='asn_description', columns='asn_cidr', values='total_byte_transferred')
    heatmap_data = heatmap_data.reindex(columns=expected_asn_cidr_order)
    
    plt.figure(figsize=(20, 10))
    log_heatmap_data = np.log10(heatmap_data.replace(0, np.nan))
    sns.heatmap(log_heatmap_data, annot=False, cmap="viridis")
    plt.title("Total Bytes Transferred per ASN and IP Prefix [Log 10 Scale]")
    plt.xticks(rotation=45)
    plt.yticks(rotation=30)
    plt.grid()
    plt.savefig("images/log_heatmap_ordered_by_byte.png")
    
    # Shannon-Wiener Index visualization
    def shannon_wiener_index(counts):
        total = sum(counts)
        proportions = [count / total for count in counts]
        return -sum(p * np.log(p) for p in proportions if p > 0)
    
    asn_diversity_by_packet = aggregated_data.groupby('asn_description')['total_packet_transferred'].sum().reset_index()
    asn_diversity_by_packet['packet_distribution'] = asn_diversity_by_packet['asn_description'].apply(lambda x : list(aggregated_data[aggregated_data['asn_description'] == x]['total_packet_transferred']))
    diversity_idx_by_packet = list(asn_diversity_by_packet['packet_distribution'].apply(lambda x: shannon_wiener_index(x)))   
    
    asn_diversity_by_byte = aggregated_data.groupby('asn_description')['total_byte_transferred'].sum().reset_index()
    asn_diversity_by_byte['packet_distribution'] = asn_diversity_by_byte['asn_description'].apply(lambda x : list(aggregated_data[aggregated_data['asn_description'] == x]['total_byte_transferred']))
    diversity_idx_by_byte = list(asn_diversity_by_byte['packet_distribution'].apply(lambda x: shannon_wiener_index(x)))
    
    asns = list(asn_diversity_by_byte['asn_description'])
    fig, ax = plt.subplots(figsize=(15, 10))
    width = 0.2
    x_pos = range(len(asns))
    
    ax.bar([p + 0.5*width for p in x_pos], diversity_idx_by_packet, width, label='Packet Transferred', color='dodgerblue')
    ax.bar([p - 0.5*width for p in x_pos], diversity_idx_by_byte, width, label='Byte Transferred', color='limegreen')
    
    ax.set_xticks(x_pos)
    ax.set_xticklabels(asns)
    ax.set_ylabel("Shannon-Wiener Index")
    ax.set_xlabel("ASN Description")
    ax.tick_params(axis='x', labelrotation=15, labelsize=8)
    ax.legend()
    ax.grid()
    ax.set_title("Shannon-Wiener Index fo Utilzed Prefixed for Each ASN")

    for i in range(len(asns)):
        ax.text(i - 0.5 * width, diversity_idx_by_packet[i] + 0.05, str(round(diversity_idx_by_packet[i], 2)), ha="center", va="bottom")
        ax.text(i + 0.5 * width, diversity_idx_by_byte[i] + 0.05, str(round(diversity_idx_by_byte[i], 2)), ha="center", va="bottom")
    
    plt.tight_layout()
    plt.savefig("images/prefix_diversity_per_asn.png")
