import re

class PingParser():
    def __init__(self, raw_text : str,
                hostname : str) -> None:
        raw_text_arr = raw_text.split(f"ping {hostname} to ")[1:]
        print(f"discovered a total of {len(raw_text_arr)} logs")
        
        self.ping_data = {}
        
        for raw_text_slice in raw_text_arr:
            self.preprocess(raw_text_slice)
            
    def preprocess(self, raw_text_slice: str):
        raw_text_slice_arr = raw_text_slice.split("\n")[:-1]
        
        # get initial marker
        marker_line_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+): (\d+) byte")
        marker_data = marker_line_pattern.search(raw_text_slice_arr[0])
        dst_ip, packet_len = marker_data.group(1), marker_data.group(2)
        instance_data = {
            "queried ip": dst_ip,
            "packet length": int(packet_len)
        }
        
        # get packet statistics
        if raw_text_slice_arr[-1].startswith("round-trip "):
            stats_idx = -2
            round_trip_info_pattern = re.compile(r"round-trip min/avg/max/stddev = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+) ms")
            round_trip_data = round_trip_info_pattern.search(raw_text_slice_arr[-1])
            instance_data.update({
                "round-trip min": float(round_trip_data.group(1)),
                "round-trip mean": float(round_trip_data.group(2)),
                "round-trip max": float(round_trip_data.group(3)),
                "round-trip stddev": float(round_trip_data.group(4))
            })
        else:
            stats_idx = -1
            instance_data.update({
                "round-trip min": None,
                "round-trip mean": None,
                "round-trip max": None,
                "round-trip stddev": None
            })
            
        stats_pattern = re.compile(r"(\d+) packets transmitted, (\d+) packets received, (\d+)% packet loss")
        stats_data = stats_pattern.search(raw_text_slice_arr[stats_idx])
        instance_data.update({
            "packet sent": int(stats_data.group(1)),
            "packet received": int(stats_data.group(2)),
            "packet loss rate": float(stats_data.group(3)) / 100.0
        })
        
        self.ping_data[instance_data["queried ip"]] = instance_data
        
    def find(self, ip_addr : str):
        return self.ping_data.get(ip_addr, {})
        
class TraceRouteParser():
    def __init__(self, raw_text: str, hostname: str) -> None:
        raw_text_slices = raw_text.split(f"traceroute from {hostname} to ")[1:]
        print(f"There are a total of {len(raw_text_slices)} instances of traceroute logs")
        self.trace_data = {}
        for raw_text_slice in raw_text_slices:
            self.preprocess(raw_text_slice)
            
    def preprocess(self, raw_text_slice: str):
        raw_text_slice_arr = raw_text_slice.split("\n")[:-1]
        queried_ip = raw_text_slice_arr[0]
        hop_discovered_pattern = re.compile(r"\d+\s+([.\d]+)\s+([.\d]+)\s+ms")
        all_hops = []
        for raw_text_entry in raw_text_slice_arr[1:]:
            search_result = hop_discovered_pattern.search(raw_text_entry)
            if not search_result:
                all_hops.append((None, -1))
            else:
                all_hops.append((search_result.group(1), float(search_result.group(2))))
        
        # not found, otherwise would not return
        if not all_hops[-1][0]:
            return
            
        self.trace_data.setdefault(queried_ip, [])
        self.trace_data[queried_ip].append(all_hops)
        
    def find(self, queried_ip):
        return self.trace_data.get(queried_ip, [])