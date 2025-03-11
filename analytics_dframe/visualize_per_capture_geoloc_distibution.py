import geoip2.database
import os, re
import matplotlib.pyplot as plt
import pandas as pd

from geopy.geocoders import Nominatim

def get_city_from_ip(ip_address, database_path):
    try:
        with geoip2.database.Reader(database_path) as reader:
            response = reader.city(ip_address)
            city_data = {
                "city": response.city.name,
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
        return city_data
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_city_from_coords(latitude, longitude):
    try:
        geolocator = Nominatim(user_agent="my_reverse_geocoder")
        location = geolocator.reverse((latitude, longitude))
        if location:
            address = location.raw['address']
            city = address.get('city', address.get('town', address.get('village', None)))
            return city
        else:
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

if __name__ == "__main__":
    database_file = "./GeoLite2-City_20250221/GeoLite2-City_20250221/GeoLite2-City.mmdb"
    root_dir = "../analytics_pcap/data/compute"
    
    csv_filenames = [instance for idx, instance in enumerate(os.listdir(root_dir)) if idx in [0, 1, 3, 4]]
    full_img_dict = {}
    domain_list = []
    max_packet, max_byte = 0, 0
    
    for csv_filename in csv_filenames:
        full_path = os.path.join(root_dir, csv_filename)
        df = pd.read_csv(full_path)
        city_list, city2id = [], {}
        data_per_city = {
            'packet_from': [],
            'packet_to': [],
            'byte_from': [],
            'byte_to': [],
        }
        
        for row_idx in range(len(df)):
            ip_addr = df.iloc[row_idx]['ip_addr']
            data = get_city_from_ip(ip_addr, database_file)
            if not data:
                curr_city = "No Data"
            elif not data['city']:
                curr_city = data['country']
            else:
                # Note: The code appears to be cut off here
                curr_city = data['city']
                
            if city2id.get(curr_city, -1) != -1:
                city_idx = city2id[curr_city]
                data_per_city['packet_from'][city_idx] += df.iloc[row_idx]['packet_from']
                data_per_city['packet_to'][city_idx] += df.iloc[row_idx]['packet_to']
                data_per_city['byte_from'][city_idx] += df.iloc[row_idx]['byte_from']
                data_per_city['byte_to'][city_idx] += df.iloc[row_idx]['byte_to']
            else:
                city2id[curr_city] = len(city_list)
                city_list.append(curr_city)
                data_per_city['packet_from'].append(df.iloc[row_idx]['packet_from'])
                data_per_city['packet_to'].append(df.iloc[row_idx]['packet_to'])
                data_per_city['byte_from'].append(df.iloc[row_idx]['byte_from'])
                data_per_city['byte_to'].append(df.iloc[row_idx]['byte_to'])
                    
        local_max_packet = max(
            max(data_per_city['packet_from']) if len(data_per_city['packet_from']) > 0 else -1,
            max(data_per_city['packet_to']) if len(data_per_city['packet_to']) > 0 else -1
        )
        local_max_byte = max(
            max(data_per_city['byte_from']) if len(data_per_city['byte_from']) > 0 else -1,
            max(data_per_city['byte_to']) if len(data_per_city['byte_to']) > 0 else -1
        )
        max_packet = max_packet if max_packet > local_max_packet else local_max_packet
        max_byte = max_byte if max_byte > local_max_byte else local_max_byte
        full_img_dict[csv_filename] = (data_per_city, city_list)
        
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    i, j = 0, -1
    width = 0.2
    
    for csv_filename, (field_name_dict, unique_ts_domains) in full_img_dict.items():
        j += 1
        if j == 2:
            i += 1
            j = 0
            
        x_pos = range(len(unique_ts_domains))  # Positions for the bars
        axes[i][j].bar([p - 1.5*width for p in x_pos], field_name_dict['packet_from'], width, label='packet_from', color='tab:blue')
        axes[i][j].bar([p - 0.5*width for p in x_pos], field_name_dict['packet_to'], width, label='packet_to', color='tab:orange')
        axes[i][j].set_ylabel('Data Points')
        axes[i][j].set_ylabel('Packets')
        axes[i][j].set_xticks(x_pos)
        axes[i][j].set_ylim(0, max_packet * 1.1)
        axes[i][j].set_ticklabels(unique_ts_domains, labelrotation=15, labelsize=6)
        
        ax2 = axes[i][j].twinx()
        ax2.bar([p+0.5*width for p in x_pos], field_name_dict['byte_from'], width, label='byte_from', color='tab:red')
        ax2.bar([p+1.5*width for p in x_pos], field_name_dict['byte_to'], width, label='byte_to', color='tab:green')
        ax2.set_ylabel('Bytes')
        ax2.set_ylim(0, max_byte * 1.1)
        
        lines_1, labels_1 = axes[i][j].get_legend_handles_labels()
        lines_2, labels_2 = ax2.get_legend_handles_labels()
        ax2.legend(lines_1 + lines_2, labels_1 + labels_2, loc="upper right")
        
        date = re.search(r"2025\[\\d\]{8}", csv_filename)
        date_str = date.group()
        year, month, day, hour, minute = date_str[4:], date_str[4:6], date_str[6:8], date_str[8:10], date_str[10:]
        data_type = (csv_filename[date.span()[0]]).rstrip("_")
        axes[i][j].set_title(f'{data_type}: {month}/{day}/{year} {hour}:{minute} Packet and Byte Transfers')
        
    plt.tight_layout()