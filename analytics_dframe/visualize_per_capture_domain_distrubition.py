import os, re
import matplotlib.pyplot as plt
import pandas as pd

if __name__ == "__main__":
    root_dir = "../data/convbyte"
    traffic_of_interest = {"streaming-netflix": [], 
                           "remoteserver-colab": [], 
                           "videocall-wechat": [], 
                           "streaming-youtube": [], 
                           "remoteserver-roboflow": [], 
                           "videocall-tecent": []}
    for instance in os.listdir(root_dir):
        header = instance.split("_")[0]
        if header in traffic_of_interest:
            traffic_of_interest[header].append(instance)

    full_img_dict = {}
    domain_list = []
    max_packet, max_byte = 0, 0
    
    for identifier, csv_filenames in traffic_of_interest.items():

        field_name_dict = {
            "packet_from": [],
            "packet_to": [],
            "byte_from": [],
            "byte_to": [] 
        }

        idx_incremental = 0
        ds2idx = {}

        for csv_filename in csv_filenames:
            full_path = os.path.join(root_dir, csv_filename)
            df = pd.read_csv(full_path)
            df['top_second_domain_name'] = df['domain_name'].map(lambda x : '.'.join(x.split('.')[-2:]))
            unique_domain_names = list(df['top_second_domain_name'].unique())
            for domain_name in unique_domain_names:
                if domain_name in ds2idx:
                    for field_name in field_name_dict.keys():
                        field_name_dict[field_name][ds2idx[domain_name]] += (int(df[df['top_second_domain_name'] == domain_name][field_name].sum()))
                else:
                    for field_name in field_name_dict.keys():
                        field_name_dict[field_name].append((int(df[df['top_second_domain_name'] == domain_name][field_name].sum())))
                    ds2idx[domain_name] = idx_incremental
                    idx_incremental += 1

        full_img_dict[identifier] = (field_name_dict, ds2idx.keys())
   
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    i, j = 0, -1
    width = 0.2
   
    for identifier, (field_name_dict, unique_ts_domains) in full_img_dict.items():
       j += 1
       if j == 3:
           i += 1
           j = 0
           
       x_pos = range(len(unique_ts_domains)) # Positions for the bars
       axes[i][j].bar([p - 1.5*width for p in x_pos], field_name_dict['packet_from'], width, label='packet_from', color='tab:blue')
       axes[i][j].bar([p - 0.5*width for p in x_pos], field_name_dict['packet_to'], width, label='packet_to', color='tab:orange')
       
       axes[i][j].set_ylabel('Data Points')
       axes[i][j].set_title('Packets')
       axes[i][j].set_xticks(x_pos)
       axes[i][j].set_xticklabels(unique_ts_domains, rotation=15) # , labelsize=8
       axes[i][j].tick_params(axis='x', labelrotation=15) # , labelsize=8
       axes[i][j].set_xticklabels(unique_ts_domains)
       
       ax2 = axes[i][j].twinx()
       
       ax2.bar([p+0.5*width for p in x_pos], field_name_dict['byte_from'], width, label='byte_from', color='tab:red')
       ax2.bar([p+1.5*width for p in x_pos], field_name_dict['byte_to'], width, label='byte_to', color='tab:green')
       
       ax2.set_ylabel('Bytes')
       # ax2.set_ylim(0, max_byte * 1.1)
       lines_1, labels_1 = axes[i][j].get_legend_handles_labels()
       lines_2, labels_2 = ax2.get_legend_handles_labels()
       ax2.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper right')

       axes[i][j].set_title(identifier)
    
    plt.tight_layout()
    plt.savefig("images/per_capture_domain_distribution.png")