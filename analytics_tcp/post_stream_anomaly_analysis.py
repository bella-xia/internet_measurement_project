import os, logging, argparse, re
import pandas as pd
from collections import defaultdict
from utils_plot_modules import produce_cdf, produce_pdf

logging.basicConfig(filename="logger.out", level=logging.INFO)
logger = logging.getLogger()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--root_dir", type=str, default="data/anomaly")
    parser.add_argument("-m", "--mode", type=str, required=True)
    parser.add_argument("-o", "--output_dir", type=str, default="images")

    args = parser.parse_args()

    captures = [capture for capture in os.listdir(args.root_dir) if capture.endswith(".csv")]

    # first store all necessary metadata in each capture
    captures_meta = []
    type_counts = {}
    packet_pattern = re.compile(r"([\w]+)-([\w]+)_(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})_(\d{4})")

    for idx, capture in enumerate(captures):
        meta = packet_pattern.search(capture)
        if meta:
            captures_meta.append({
                "capture": capture,
                "type": meta.group(1),
                "identifier": meta.group(2),
                "ts": f"{meta.group(4)}/{meta.group(5)} {meta.group(6)}:{meta.group(7)}"
            })
            type_counts.setdefault(meta.group(1), {})
            type_counts[meta.group(1)].setdefault(meta.group(2), [])
            type_counts[meta.group(1)][meta.group(2)].append(idx)
    
    if args.mode == "anomaly":
        for k, v in type_counts.items():
            print(f"captured {len(v)} instances of {k}: {v}")

            if len(v) > 1:

                retrans :list[tuple[list, str]] = []
                dupacks:list[tuple[list, str]] = []
                outoforders:list[tuple[list, str]] = []

                for (v_ident, v_set) in v.items():

                    retrans_arr, outoforders_arr, dupakcs_arr = [], [], [] 
                    
                    for v_ins in v_set:

                        full_path = os.path.join(args.root_dir, captures_meta[v_ins]['capture'])
                        df = pd.read_csv(full_path)

                        retrans_arr.extend([num for num in df['num_retransmission'] if (num != 0 and num < 2000)])
                        outoforders_arr.extend([num for num in df['num_outoforder'] if (num != 0  and num < 2000)])
                        dupakcs_arr.extend([num for num in df['num_duplicate_ack'] if num != 0])
                    
                    retrans.append((retrans_arr, captures_meta[v_ins]['identifier']))
                    outoforders.append((outoforders_arr, captures_meta[v_ins]['identifier']))
                    dupacks.append((dupakcs_arr, captures_meta[v_ins]['identifier']))

                produce_pdf(retrans, savename=f"{args.output_dir}/{args.mode}/{k}_retransmit_his.png",
                            x_unit="packets", title=f"{k} Retransmitted Packet Histogram", density=False, ylogscale=True,
                            ylabel="Stream Number [Log Scale]")
                produce_pdf(outoforders, savename=f"{args.output_dir}/{args.mode}/{k}_outoforder_his.png",
                            x_unit="packets", title=f"{k} Out-of-order Packet Histogram", density=False, ylogscale=True,
                            ylabel="Stream Number [Log Scale]")
                produce_pdf(dupacks, savename=f"{args.output_dir}/{args.mode}/{k}_duplicate_ack_his.png",
                            x_unit="packets", title=f"{k} Duplicate Acknowledgement Histogram", density=False, ylogscale=True,
                            ylabel="Stream Number [Log Scale]")