import os, logging, argparse, re
import pandas as pd
from collections import defaultdict
from utils_plot_modules import produce_cdf, produce_pdf

logging.basicConfig(filename="logger.out", level=logging.INFO)
logger = logging.getLogger()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--root_dir", type=str, default="data")
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
    
    if args.mode == "comparative":
        for k, v in type_counts.items():
            print(f"captured {len(v)} instances of {k}:")
            print(v)

            # if there is more than 1 instances, plot to get 
            if len(v) > 1:

                rtt_avgs: list[tuple[list, str]] = []
                s2c_rtt_avgs: list[tuple[list, str]] = []
                c2s_rtt_avgs: list[tuple[list, str]] = []

                win_avgs: list[tuple[list, str]] = []
                s2c_win_avgs: list[tuple[list, str]] = []
                c2s_win_avgs: list[tuple[list, str]] = []

                hdsk_avgs: list[tuple[list, str]] = []
                tls_hdsk_avgs: list[tuple[list, str]] = []

                retrans :list[tuple[list, str]] = []
                dupacks:list[tuple[list, str]] = []
                outoforders:list[tuple[list, str]] = []

                for (v_ident, v_set) in v.items():

                    rtt_arr, s2c_rtt_arr, c2s_rtt_arr = [], [], []
                    win_arr, s2c_win_arr, c2s_win_arr = [], [], [] 
                    retrans_arr, outoforders_arr, dupakcs_arr = [], [], [] 
                    hdsk_arr, tls_hdsk_arr = [], []
                    
                    for v_ins in v_set:

                        full_path = os.path.join(args.root_dir, captures_meta[v_ins]['capture'])
                        df = pd.read_csv(full_path)

                        rtt_arr.extend(list(df['rtt_avg']))
                        s2c_rtt_arr.extend(list(df['dst2src_rtt_avg']))
                        c2s_rtt_arr.extend(list(df['src2dst_rtt_avg']))

                        win_arr.extend(list(df['window_avg']))
                        s2c_win_arr.extend(list(df['dst2src_window_avg']))
                        c2s_win_arr.extend(list(df['src2dst_window_avg']))

                        retrans_arr.extend(list(df['num_retransmission']))
                        outoforders_arr.extend(list(df['num_outoforder']))
                        dupakcs_arr.extend(list(df['num_duplicate_ack']))

                        hdsk = list(df[df['handshake_duration'] > 0.0]['handshake_duration'])
                        hdsk_arr.extend(hdsk)

                        tls_hdsk = list(df[df['tls_handshake_duration'] > 0.0]['tls_handshake_duration'])
                        tls_hdsk_arr.extend(tls_hdsk)

                    rtt_avgs.append((rtt_arr, captures_meta[v_ins]['identifier']))
                    s2c_rtt_avgs.append((s2c_rtt_arr, captures_meta[v_ins]['identifier']))
                    c2s_rtt_avgs.append((c2s_rtt_arr, captures_meta[v_ins]['identifier']))

                    win_avgs.append((win_arr, captures_meta[v_ins]['identifier']))
                    s2c_win_avgs.append((s2c_win_arr, captures_meta[v_ins]['identifier']))
                    c2s_win_avgs.append((c2s_win_arr, captures_meta[v_ins]['identifier']))

                    retrans.append((retrans_arr, captures_meta[v_ins]['identifier']))
                    outoforders.append((outoforders_arr, captures_meta[v_ins]['identifier']))
                    dupacks.append((dupakcs_arr, captures_meta[v_ins]['identifier']))

                    if len(hdsk_arr) > 0:
                        hdsk_avgs.append((hdsk_arr, captures_meta[v_ins]['identifier']))

                    if len(tls_hdsk_arr) > 0:
                        tls_hdsk_avgs.append((tls_hdsk_arr, captures_meta[v_ins]['identifier']))
                
                produce_pdf(rtt_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_rtt_avg_pdf.png",
                            x_unit="rtt (s)", title=f"{k} Average Round-Trip Time PDF")
                produce_cdf(rtt_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_rtt_avg_cdf.png",
                            x_unit="rtt (s) [log scale]", title=f"{k} Average Round-Trip Time CDF", logscale=True)

                produce_pdf(s2c_rtt_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_s2c_rtt_avg_pdf.png",
                            x_unit="rtt (s)", title=f"{k} Average Server-to-Client Round-Trip Time PDF")
                produce_cdf(s2c_rtt_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_s2c_rtt_avg_cdf.png",
                            x_unit="rtt (s) [log scale]", title=f"{k} Average Server-to-Client Round-Trip Time CDF", logscale=True)

                produce_pdf(c2s_rtt_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_c2s_rtt_avg_pdf.png",
                            x_unit="rtt (s)", title=f"{k} Average Client-to-Server Round-Trip Time PDF")
                produce_cdf(c2s_rtt_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_c2s_rtt_avg_cdf.png",
                            x_unit="rtt (s) [log scale]", title=f"{k} Average Client-to-Server Round-Trip Time CDF", logscale=True)
        
                produce_pdf(win_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_win_avg_pdf.png",
                            x_unit="window size (byte)", title=f"{k} Average Window Size PDF")
                produce_cdf(win_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_win_avg_cdf.png",
                            x_unit="window size (byte) [log scale]", title=f"{k} Average Window Size CDF", logscale=True)

                produce_pdf(s2c_win_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_s2c_win_avg_pdf.png",
                            x_unit="window size (byte)", title=f"{k} Average Server-to-Client Window Size PDF")
                produce_cdf(s2c_win_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_s2c_win_avg_cdf.png",
                            x_unit="window size (byte) [log scale]", title=f"{k} Average Server-to-Client Window Size CDF", logscale=True)

                produce_pdf(c2s_win_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_c2s_win_avg_pdf.png",
                            x_unit="window size (byte)", title=f"{k} Average Client-to-Server Window Size PDF")
                produce_cdf(c2s_win_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_c2s_win_avg_cdf.png",
                            x_unit="window size (byte) [log scale]", title=f"{k} Average Client-to-Server Window Size CDF", logscale=True)

                produce_pdf(hdsk_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_handshake_duration_pdf.png",
                            x_unit="duration (s)", title=f"{k} TCP handshake duration PDF")
                produce_cdf(hdsk_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_handshake_duration_cdf.png",
                            x_unit="duration (s)", title=f"{k} TCP handshake duration CDF")
                
                produce_pdf(tls_hdsk_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_tls_handshake_duration_pdf.png",
                            x_unit="duration (s)", title=f"{k} TLS handshake duration PDF")
                produce_cdf(tls_hdsk_avgs, savename=f"{args.output_dir}/{args.mode}/{k}_tls_handshake_duration_cdf.png",
                            x_unit="duration (s)", title=f"{k} TLS handshake duration CDF")

                produce_pdf(retrans, savename=f"{args.output_dir}/{args.mode}/{k}_retransmit_his.png",
                            x_unit="packets", title=f"{k} Retransmitted Packets Histogram", density=False)
                produce_pdf(outoforders, savename=f"{args.output_dir}/{args.mode}/{k}_outoforder_his.png",
                            x_unit="packets", title=f"{k} Out-of-order Packets Histogram", density=False)
                produce_pdf(dupacks, savename=f"{args.output_dir}/{args.mode}/{k}_duplicate_ack_his.png",
                            x_unit="packets", title=f"{k} Duplicate Acknowledgements Histogram", density=False)