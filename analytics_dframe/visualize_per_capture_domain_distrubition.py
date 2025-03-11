import os, re
import matplotlib.pyplot as plt
import pandas as pd

if __name__ == "__main__":
   root_dir = "../analytics_pcap/data/convbyte"
   csv_filenames = [instance for idx, instance in enumerate(os.listdir(root_dir)) if idx in [0, 1, 3, 4]]
   full_img_dict = {}
   domain_list = []
   max_packet, max_byte = 0, 0
   
   for csv_filename in csv_filenames:
       full_path = os.path.join(root_dir, csv_filename)
       df = pd.read_csv(full_path)
       df['top_second_domain_name'] = df['domain_name'].map(lambda x : '.'.join(x.split('.')[-2:]))
       field_name_dict = {
           "packet_from": [],
           "packet_to": [],
           "byte_from": [],
           "byte_to": [] 
       }
       
       unique_ts_domains = set(df['top_second_domain_name'].unique())
       for ts_domain in unique_ts_domains:
           for field_name in field_name_dict.keys():
               field_name_dict[field_name].append(int(df[df['top_second_domain_name'] == ts_domain][field_name].sum()))
               
       local_max_packet = max(max(field_name_dict['packet_from']), max(field_name_dict['packet_to']))
       local_max_byte = max(max(field_name_dict['byte_from']), max(field_name_dict['byte_to']))
       max_packet = max_packet if max_packet > local_max_packet else local_max_packet
       max_byte = max_byte if max_byte > local_max_byte else local_max_byte
       full_img_dict[csv_filename] = (field_name_dict, unique_ts_domains)
       
   fig, axes = plt.subplots(2, 2, figsize=(15, 10))
   i, j = 0, -1
   width = 0.2
   
   for csv_filename, (field_name_dict, unique_ts_domains) in full_img_dict.items():
       j += 1
       if j == 2:
           i += 1
           j = 0
           
       x_pos = range(len(unique_ts_domains)) # Positions for the bars
       axes[i][j].bar([p - 1.5*width for p in x_pos], field_name_dict['packet_from'], width, label='packet_from', color='tab:blue')
       axes[i][j].bar([p - 0.5*width for p in x_pos], field_name_dict['packet_to'], width, label='packet_to', color='tab:orange')
       
       axes[i][j].set_ylabel('Data Points')
       axes[i][j].set_title('Packets')
       axes[i][j].set_xticks(x_pos)
       axes[i][j].set_xticklabels(unique_ts_domains, rotation=15, labelsize=8)
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
       
       date = re.search(r"2023(\d{6})", csv_filename)
       date_str = date.group()
       year, month, day, hour, minute = date_str[:4], date_str[4:6], date_str[6:8], date_str[8:10], date_str[10:]
       data_type = (csv_filename[:date.span()[0]]).rstrip("_")

       axes[i][j].set_title(f"{data_type}: {month}/{day}/{year} {hour}:{minute} Packet and Byte Transfers")
    
   plt.tight_layout()
   plt.savefig("images/per_capture_domain_distribution.png")