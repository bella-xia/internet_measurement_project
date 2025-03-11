import os, re
import matplotlib.pyplot as plt
import pandas as pd

if __name__ == "__main__":
    root_dir = "../analytics_pcap/data/convbyte"
    as_metadata_info_dir = "data/ip_geoloc_domain_mapping.csv"
    csv_filenames = [instance for idx, instance in enumerate(os.listdir(root_dir)) if idx in [0, 1, 3, 4]]
    max_packet, max_byte = 0, 0
    as_metadata_df = pd.read_csv(as_metadata_info_dir)
    full_asn_img_dict = {}
    full_asn_description_img_dict = {}
    full_asn_description_img_dict, full_asn_img_dict = {}, {}
    
    for csv_filename in csv_filenames:
        full_path = os.path.join(root_dir, csv_filename)
        df = pd.read_csv(full_path)
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
        
        for row_idx in range(len(df)):
            ip_addr = df.iloc[row_idx]['ip_addr']
            data = as_metadata_df[as_metadata_df['ip_addr'].iloc[0] == ip_addr].iloc[0]
            asn_description, asn = data['asn_description'], (str(data['asn']) + " (" + str(data['asn_description']) + ")")
            
            if asn2id.get(asn, -1) != -1:
                asn_idx = asn2id[asn]
                data_per_asn['packet_from'][asn_idx] += df.iloc[row_idx]['packet_from']
                data_per_asn['packet_to'][asn_idx] += df.iloc[row_idx]['packet_to']
                data_per_asn['byte_from'][asn_idx] += df.iloc[row_idx]['byte_from']
                data_per_asn['byte_to'][asn_idx] += df.iloc[row_idx]['byte_to']
            else:
                asn2id[asn] = len(asn_list)
                asn_list.append(asn)
                data_per_asn['packet_from'].append(df.iloc[row_idx]['packet_from'])
                data_per_asn['packet_to'].append(df.iloc[row_idx]['packet_to'])
                data_per_asn['byte_from'].append(df.iloc[row_idx]['byte_from'])
                data_per_asn['byte_to'].append(df.iloc[row_idx]['byte_to'])
            
            if asn_descrip2id.get(asn_description, -1) != -1:
                asn_descrip_idx = asn_descrip2id[asn_description]
                data_per_asn_description['packet_from'][asn_descrip_idx] += df.iloc[row_idx]['packet_from']
                data_per_asn_description['packet_to'][asn_descrip_idx] += df.iloc[row_idx]['packet_to']
                data_per_asn_description['byte_from'][asn_descrip_idx] += df.iloc[row_idx]['byte_from']
                data_per_asn_description['byte_to'][asn_descrip_idx] += df.iloc[row_idx]['byte_to']
            else:
                asn_descrip2id[asn_description] = len(asn_descrip_list)
                asn_descrip_list.append(asn_description)
                data_per_asn_description['packet_from'].append(df.iloc[row_idx]['packet_from'])
                data_per_asn_description['packet_to'].append(df.iloc[row_idx]['packet_to'])
                data_per_asn_description['byte_from'].append(df.iloc[row_idx]['byte_from'])
                data_per_asn_description['byte_to'].append(df.iloc[row_idx]['byte_to'])

        local_max_packet = max(
            max(data_per_asn['packet_from']) if len(data_per_asn['packet_from']) > 0 else -1,
            max(data_per_asn['packet_to']) if len(data_per_asn['packet_to']) > 0 else -1
        )
        local_max_byte = max(
            max(data_per_asn['byte_from']) if len(data_per_asn['byte_from']) > 0 else -1,
            max(data_per_asn['byte_to']) if len(data_per_asn['byte_to']) > 0 else -1
        )
        max_packet = max_packet if max_packet > local_max_packet else local_max_packet
        max_byte = max_byte if max_byte > local_max_byte else local_max_byte
        full_asn_img_dict[csv_filename] = (data_per_asn, asn_list)
        full_asn_description_img_dict[csv_filename] = (data_per_asn_description, asn_descrip_list)
    
    width = 0.2
    
    for data, output_dir in [(full_asn_img_dict, "images/per_capture_asn_distribution.png"),
                             (full_asn_description_img_dict, "images/per_capture_asn_name_distribution.png")]:
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        i, j = 0, -1
        for csv_filename, (field_name_dict, unique_ts_domains) in data.items():
            j += 1
            if j == 2:
                i += 1
                j = 0
                
            x_pos = range(len(unique_ts_domains))  # Positions for the bars
            axes[i][j].bar([p - 1.5*width for p in x_pos], field_name_dict['packet_from'], width, label='packet_from', color='tab:blue')
            axes[i][j].bar([p - 0.5*width for p in x_pos], field_name_dict['packet_to'], width, label='packet_to', color='tab:orange')
            
            axes[i][j].set_xlabel('Data Points')
            axes[i][j].set_ylabel('Packets')
            axes[i][j].set_xticks(x_pos)
            axes[i][j].set_ylim(0, max_packet * 1.1)
            axes[i][j].tick_params(axis='x', labelrotation=15, labelsize=8)
            axes[i][j].set_xticklabels(unique_ts_domains)
            
            ax2 = axes[i][j].twinx()
            
            ax2.bar([p+0.5*width for p in x_pos], field_name_dict['byte_from'], width, label='byte_from', color='tab:red')
            ax2.bar([p+1.5*width for p in x_pos], field_name_dict['byte_to'], width, label='byte_to', color='tab:green')
            
            ax2.set_ylabel('Bytes')
            ax2.set_ylim(0, max_byte * 1.1)
            lines_1, labels_1 = axes[i][j].get_legend_handles_labels()
            lines_2, labels_2 = ax2.get_legend_handles_labels()
            ax2.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper right')
            
            date = re.search(r"2025[\d]{6}", csv_filename)
            date_str = date.group()
            year, month, day, hour, minute = date_str[0:4], date_str[4:6], date_str[6:8], date_str[8:10], date_str[10:]
            data_type = (csv_filename[0:date.span()[0]]).rstrip("_")
            axes[i][j].set_title(f'{data_type}: {month}/{day}/{year} {hour}:{minute} Packet and Byte Transfers')
        plt.tight_layout()
        plt.savefig(output_dir)