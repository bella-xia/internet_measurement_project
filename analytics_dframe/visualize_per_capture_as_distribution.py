import os, re
import matplotlib.pyplot as plt
import pandas as pd

if __name__ == "__main__":
    root_dir = "../analytics_pcap/data/convbyte"
    as_metadata_info_dir = "data/ip_geoloc_domain_mapping.csv"
    traffic_of_interest = {"streaming-netflix": [], 
                           "remoteserver-colab": [], 
                           "videocall-wechat": [], 
                           "streaming-youtube": [], 
                           "remoteserver-roboflow": [], 
                          "videocall-tencent": []
                          }
    for instance in os.listdir(root_dir):
        header = instance.split("_")[0]
        if header in traffic_of_interest:
            traffic_of_interest[header].append(instance)
   
    max_packet, max_byte = 0, 0
    as_metadata_df = pd.read_csv(as_metadata_info_dir)
    full_asn_img_dict = {}
    full_asn_description_img_dict = {}
    full_asn_description_img_dict, full_asn_img_dict = {}, {}
    
    for identifier, csv_filenames in traffic_of_interest.items():
        asn_list, asn2id = [], {}
        asn_descrip_list, asn_descrip2id = [], {}
        data_per_asn_description = {
            'packet_from': [],
            'packet_to': [],
            'byte_from': [],
            'byte_to': [],
        }
        data_per_asn = {
            'packet_from': [],
            'packet_to': [],
            'byte_from': [],
            'byte_to': [],
        }

        for csv_filename in csv_filenames:
            full_path = os.path.join(root_dir, csv_filename)
            df = pd.read_csv(full_path)

            for row_idx in range(len(df)):
                instance =  df.iloc[row_idx]
                ip_addr = instance['ip_addr']
                data = as_metadata_df[as_metadata_df['ip_addr'] == ip_addr].iloc[0]
                asn_description, asn = (str(data['asn_description']).split(",")[0] if len(str(data['asn_description'])) < 15 else str(data['asn_description']).split("-")[0]), (str(data['asn']) + " (" + (str(data['asn_description']).split(",")[0] if len(str(data['asn_description'])) < 10 else str(data['asn_description']).split("-")[0]) + ")")
            
                if asn2id.get(asn, -1) != -1:
                    asn_idx = asn2id[asn]
                    data_per_asn['packet_from'][asn_idx] += instance['packet_from']
                    data_per_asn['packet_to'][asn_idx] += instance['packet_to']
                    data_per_asn['byte_from'][asn_idx] += instance['byte_from']
                    data_per_asn['byte_to'][asn_idx] += instance['byte_to']
                else:
                    asn2id[asn] = len(asn_list)
                    asn_list.append(asn)
                    data_per_asn['packet_from'].append(instance['packet_from'])
                    data_per_asn['packet_to'].append(instance['packet_to'])
                    data_per_asn['byte_from'].append(instance['byte_from'])
                    data_per_asn['byte_to'].append(instance['byte_to'])
            
                if asn_descrip2id.get(asn_description, -1) != -1:
                    asn_descrip_idx = asn_descrip2id[asn_description]
                    data_per_asn_description['packet_from'][asn_descrip_idx] += instance['packet_from']
                    data_per_asn_description['packet_to'][asn_descrip_idx] += instance['packet_to']
                    data_per_asn_description['byte_from'][asn_descrip_idx] += instance['byte_from']
                    data_per_asn_description['byte_to'][asn_descrip_idx] += instance['byte_to']
                else:
                    asn_descrip2id[asn_description] = len(asn_descrip_list)
                    asn_descrip_list.append(asn_description)
                    data_per_asn_description['packet_from'].append(instance['packet_from'])
                    data_per_asn_description['packet_to'].append(instance['packet_to'])
                    data_per_asn_description['byte_from'].append(instance['byte_from'])
                    data_per_asn_description['byte_to'].append(instance['byte_to'])

        full_asn_img_dict[identifier] = ({k: [x / len(csv_filenames) for x in v] for k, v in data_per_asn.items()}, 
                                         asn_list)
        full_asn_description_img_dict[identifier] = ({k: [x / len(csv_filenames) for x in v] for k, v in data_per_asn_description.items()}, 
                                                    asn_descrip_list)
    
    width = 0.2
    
    for data, output_dir in [(full_asn_img_dict, "images/per_capture_asn_distribution.png"),
                             (full_asn_description_img_dict, "images/per_capture_asn_name_distribution.png")]:
        fig, axes = plt.subplots(2, 3, figsize=(18, 10))
        i, j = 0, -1
        for identifier, (field_name_dict, unique_ts_domains) in data.items():
            j += 1
            if j == 3:
                i += 1
                j = 0
            if i == 2:
                break
                
            x_pos = range(len(unique_ts_domains))  # Positions for the bars
            axes[i][j].bar([p - 1.5*width for p in x_pos], field_name_dict['packet_from'], width, label='packet_from', color='tab:blue')
            axes[i][j].bar([p - 0.5*width for p in x_pos], field_name_dict['packet_to'], width, label='packet_to', color='tab:orange')
            
            axes[i][j].set_xlabel('Data Points')
            axes[i][j].set_ylabel('Packets')
            axes[i][j].set_xticks(x_pos)
            # axes[i][j].set_ylim(0, max_packet * 1.1)
            axes[i][j].tick_params(axis='x', labelrotation=15, labelsize=8)
            axes[i][j].set_xticklabels(unique_ts_domains)
            
            ax2 = axes[i][j].twinx()
            
            ax2.bar([p+0.5*width for p in x_pos], field_name_dict['byte_from'], width, label='byte_from', color='tab:red')
            ax2.bar([p+1.5*width for p in x_pos], field_name_dict['byte_to'], width, label='byte_to', color='tab:green')
            
            ax2.set_ylabel('Bytes')
            # ax2.set_ylim(0, max_byte * 1.1)
            lines_1, labels_1 = axes[i][j].get_legend_handles_labels()
            lines_2, labels_2 = ax2.get_legend_handles_labels()
            ax2.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper right')
            
            # date = re.search(r"2025[\d]{6}", csv_filename)
            # date_str = date.group()
            # year, month, day, hour, minute = date_str[0:4], date_str[4:6], date_str[6:8], date_str[8:10], date_str[10:]
            # data_type = (csv_filename[0:date.span()[0]]).rstrip("_")
            # axes[i][j].set_title(f'{data_type}: {month}/{day}/{year} {hour}:{minute} Packet and Byte Transfers')
            axes[i][j].set_title(identifier)
        plt.tight_layout()
        plt.savefig(output_dir)