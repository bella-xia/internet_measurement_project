import pandas as pd
import numpy as np
from tqdm import tqdm
import subprocess, argparse, time


TARGET_AS = ['AS-SSI, US',
             'AMAZON-02, US',
             'CANONICAL-AS, GB',
             # 'MICROSOFT-CORP-MSN-AS-BLOCK, US',
             'GOOGLE, US',
             # 'AMAZON-AES, US',
             'TENCENT-NET-AP-CN Tencent Building, Kejizhongyi Avenue, CN',
             'AKAMAI-ASN1, NL',
             'CLOUDFLARENET, US',
             # 'GOOGLE-CLOUD-PLATFORM, US',
             'COMCAST-7922, US',
             'CHINAMOBILE-CN China Mobile Communications Group Co., Ltd., CN',
             'TAOBAO Zhejiang Taobao Network Co.,Ltd, CN',
             'ZEN-ECN, US',
             'CHINANET-SH-AP China Telecom Group, CN' 'CDSC-AS1, US',
             'ML-1432-54994, CA',
             'ALIBABA-CN-NET Alibaba US Technology Co., Ltd., CN',
             'AKAMAI-AS, US',
             # 'GITHUB, US',
             # 'ACE-AS-AP ACE, SG',
             # 'FASTLY, US',
             # 'FACEBOOK, US',
             'CLOUDFLARESPECTRUM Cloudflare, Inc., US',
             'CHINA169-BACKBONE CHINA UNICOM China169 Backbone, CN',
             'CISCO-UMBRELLA, US',
             # 'CDN77 _, GB',
             # 'LEASEWEB-USA-WDC, US',
             # 'FSNET-1, US',
             'NEXTDNS, US',
             'QUAD9-AS-1, US',
             'ADGUARD, CY',
             'AVAST-AS-DC Gen Digital dba as Avast, CZ',
             # 'CORIX-999, US',
             'UNICOM-SHFT-IDC China Unicom Shanghai FuTe IDC network, CN']

def process_ping_commands(dest, fd, probe_count=5):
    subprocess.run(["scamper", "-I", f"ping -c {str(probe_count)} {dest}"], stdout=fd, stderr=subprocess.STDOUT)
    fd.flush()
    time.sleep(1)

def process_traceroute_commands(dest, fd, probe_count=5):
    for _ in range(probe_count):
        subprocess.run(["scamper", "-i", dest], stdout=fd, stderr=subprocess.STDOUT)
        fd.flush()
        time.sleep(1)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--input_dir", type=str, default="../analytics_dframe/data/ip_geoloc_domain_mapping.csv")
    parser.add_argument("--trace_output_dir", type=str, default="tracelog.out")
    parser.add_argument("--ping_output_dir", type=str, default="pinglog.out")
    parser.add_argument("--num_ping", type=int, default=30)
    parser.add_argument("--num_trace", type=int, default=10)
    parser.add_argument("--topn", type=int, default=1)
    parser.add_argument("--mode", type=str, default="ping")

    args = parser.parse_args()

    df = pd.read_csv(args.input_dir)

    all_queriable_ip = {}
    for as_ins in TARGET_AS:
        filtered_df = df[df['asn_description'] == as_ins].sort_values(by="total_byte_transferred", ascending=False)
        ip_list = list(filtered_df['ip_addr'])
        all_queriable_ip[as_ins] = ip_list if len(ip_list) < args.topn else ip_list[:args.topn]
    
    if args.mode == "ping":
        with open(args.ping_output_dir, "w") as f:
            for k, v in tqdm(all_queriable_ip.items()):
                for ip_addr in v:
                    process_ping_commands(ip_addr, f, probe_count=args.num_ping)
    elif args.mode == "trace":
        with open(args.trace_output_dir, "w") as f:
            for k, v in tqdm(all_queriable_ip.items()):
                for ip_addr in v:
                    process_traceroute_commands(ip_addr, f, probe_count = args.num_trace)