import geoip2.database
import os, csv
from ipwhois import IPWhois
import pandas as pd
from tqdm import tqdm, trange

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

if __name__ == "__main__":
    database_file = "/GeoLite2-City_20250221/GeoLite2-City_20250221/GeoLite2-City.mmdb"
    root_dir = ".../analytics_pcap/data/convoy/byte"
    dict_data = {}
    
    csv_filenames = os.listdir(root_dir)
    
    for csv_filename in tqdm(csv_filenames):
        df = pd.read_csv(os.path.join(root_dir, csv_filename))
        for idx in trange(len(df)):
            instance = df.iloc[idx]
            domain_name_split_by_level = instance['domain_name'].split('.')
            if instance['ip_addr'] not in dict_data:
                dict_data[instance['ip_addr']] = {'domain_name': instance['domain_name'],
                                               'total_byte_transferred': instance['byte_from'],
                                               'total_packet_transferred': instance['packet_from'],
                                               'top_level_domain': domain_name_split_by_level[-1],
                                               'second_level_domain': domain_name_split_by_level[-2]
                                              }
            geoloc_data = get_city_from_ip(instance['ip_addr'], database_file)
            if not geoloc_data:
                dict_data[instance['ip_addr']]['city'] = 'NoData'
                dict_data[instance['ip_addr']]['country'] = 'NoData'
            elif not geoloc_data['city']:
                dict_data[instance['ip_addr']]['city'] = 'CoarseRecord'
                dict_data[instance['ip_addr']]['country'] = geoloc_data['country']
            else:
                dict_data[instance['ip_addr']]['city'] = geoloc_data['city']
                dict_data[instance['ip_addr']]['country'] = geoloc_data['country']
            
            asn_data = IPWhois(instance['ip_addr']).lookup_rdap()
            dict_data[instance['ip_addr']]['asn_registry'] = asn_data['asn_registry']
            dict_data[instance['ip_addr']]['asn'] = asn_data['asn']
            dict_data[instance['ip_addr']]['asn_description'] = asn_data['asn_description']
            dict_data[instance['ip_addr']]['asn_cidr'] = asn_data['asn_cidr']
        else:
            dict_data[instance['ip_addr']]['total_byte_transferred'] += instance['byte_from']
            dict_data[instance['ip_addr']]['total_packet_transferred'] += instance['packet_from']
            
    with open("data/ip_geoloc_domain_mapping.csv", "w") as f:
        writer = csv.writer(f, delimiter=',')
        writer.writerow(['ip_addr', 'domain_name', 'top_level_domain', 'second_level_domain',
                        'city', 'country',
                        'asn_registry', 'asn', 'asn_description', 'asn_cidr',
                        'total_byte_transferred', 'total_packet_transferred'])
        
        for key, values in dict_data.items():
            writer.writerow([key, values['domain_name'], values['top_level_domain'], values['second_level_domain'],
                            values['city'], values['country'],
                            values['asn_registry'], values['asn'], values['asn_description'], values['asn_cidr'],
                            values['total_byte_transferred'], values['total_packet_transferred']])