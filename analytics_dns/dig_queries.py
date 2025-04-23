import subprocess, re, json, argparse
from tqdm import tqdm
import pandas as pd
import time

CAT_OF_INTEREST = {"NS", "A", "AAAA"}

class DigRecordParser:

    def __init__(self):
        self.all_data = {}

    def parse(self, domain_name: str, text: str):

        self.all_data.setdefault(domain_name, {"errrecords": {}})

        hierarchical_info = text.split('\n\n')[:-1]
        for info in hierarchical_info:
            self.parser_level(domain_name, info)
    
    def parser_level(self, domain_name: str, lev_text: str):
        records = lev_text.split("\n")

        lev_name = ""

        for record in records[:-1]:
            filtered_data = re.sub(r"\t+", r"\t", record)
            data = filtered_data.split('\t')
            if len(data) == 5 and data[-2] in CAT_OF_INTEREST:
                if len(lev_name) == 0:
                    lev_name = data[0] + "-" + data[-2]
                    self.all_data[domain_name].setdefault(lev_name, {
                        "data": [],
                        "querytime": -1,
                        "nameserver" : "" 
                    })
                self.all_data[domain_name][lev_name]['data'].append(data[-1])
            elif record.startswith(";;"):
                search_result = re.search(r";; UDP setup with ([^\s]+) for [^\s]+ failed: ([^\.]+).", record)
                if search_result:
                    self.all_data[domain_name]['errrecords'].setdefault(search_result.group(2), [])
                    self.all_data[domain_name]['errrecords'][search_result.group(2)].append(search_result.group(1))

        if len(lev_name) > 0:
            search_result = re.search(r";; Received \d+ bytes from ([\d\.]+)#53([^\s]+) in (\d+) ms", records[-1])
            if search_result:
                self.all_data[domain_name][lev_name]['nameserver'] = search_result.group(1) + " " + search_result.group(2)
                self.all_data[domain_name][lev_name]['querytime'] = int(search_result.group(3))

def run_trace_dig(domain):
    result = subprocess.run(["dig", "+trace", domain], capture_output=True, text=True)
    return result.stdout

def run_dig(domain, server):
    if server == "default":
        result = subprocess.run(["dig", domain], capture_output=True, text=True)
    else:
        result = subprocess.run(["dig", f"@{server}", domain], capture_output=True, text=True)
    return result.stdout

if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--input_dir", type=str, default="../data/Tranco_first_1000.csv")
    parser.add_argument("-n", "--topn", type=int, default=5)
    parser.add_argument("-m", "--mode", type=str, required=True)
    args = parser.parse_args()

    df = pd.read_csv(args.input_dir)
    top_dns = [df.iloc[idx]['domain'] for idx in range(len(df))]

    if args.mode == "trace":

        parser = DigRecordParser()
        for dn in tqdm(top_dns[:args.topn]):
            dns_log = run_trace_dig(dn)
            parser.parse(dn, dns_log)
            time.sleep(0.5)
    
        with open(f"Tranco_top{args.topn}_digtrace_dns_query.json", "w") as f:
            json.dump(parser.all_data, f, indent=4)
    
    elif args.mode == "server":
        testing_servers = ["default", "1.1.1.1", "8.8.4.4", "208.67.222.222"]
        query_time_pattern = re.compile(r";; Query time: (\d+) msec")
        result = {k: {} for k in testing_servers}
        for dn in tqdm(top_dns[:args.topn]):
            for server in testing_servers:

                dns_log = run_dig(dn, server=server)
                ts_pattern = query_time_pattern.search(dns_log)
                if ts_pattern:
                    result[server][dn] = {f"{dn}.-A": {"querytime": int(ts_pattern.group(1))}}
                
                time.sleep(0.5)
        
        
        for k, v in result.items():
            with open(f"Tranco_top{args.topn}_{k}_server_dns_query.json", "w") as f:
                json.dump(v, f, indent=4)
