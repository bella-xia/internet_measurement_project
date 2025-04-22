import subprocess, re, json
from tqdm import tqdm
import pandas as pd

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

def run_dig(domain, server="default"):
    if server == "default":
        result = subprocess.run(["dig", "+trace", domain], capture_output=True, text=True)
    else:
        result = subprocess.run(["dig", "+trace", f"@{server}", domain], capture_output=True, text=True)
    return result.stdout


if __name__ == '__main__':
    df = pd.read_csv("../data/Tranco_first_1000.csv")
    top_dns = [df.iloc[idx]['domain'] for idx in range(len(df))]

    for server in ["default", "8.8.4.4", "1.1.1.1", "208.67.222.222"]: # default, google, cloudfare, opendns
        # if server == "default":
        #     continue
        parser = DigRecordParser()
        for dn in tqdm(top_dns[:100]):
            dns_log = run_dig(dn, server=server)
            parser.parse(dn, dns_log)
    
        with open(f"Tranco_top100_{server}_dns_query.json", "w") as f:
            json.dump(parser.all_data, f, indent=4)
        
        exit(0)