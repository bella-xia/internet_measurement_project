import geoip2.database
import argparse

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
    parser = argparse.ArgumentParser()

    parser.add_argument("--data_dir", type=str, default="/home/bella-xia/internet_measurement_project/GeoLite2-City_20250221/GeoLite2-City.mmdb")
    parser.add_argument("-i", "--ip_query", type=str, required=True)
    args = parser.parse_args()

    data = get_city_from_ip(args.ip_query, args.data_dir)
    print(f"ip address {args.ip_query} is located at:")
    print(data)