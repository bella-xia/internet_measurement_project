import subprocess, datetime, os, csv, argparse

def run_sting(ip_addr, num_probes, dest_port, interval, maxwait):
    src_port = 10000 + os.getpid() % 50000  #semi-random port number

    cmd = [
    "scamper",
    "-I",
    f"sting -c {num_probes} -d {dest_port} -s {src_port} -i {interval} -m {maxwait} {ip_addr}"]
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        return (ip_addr, result)
    except subprocess.TimeoutExpired:
        return (ip_addr, "TIMEOUT")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--ip_addr", type=str, default="148.153.56.163") # defaulting ip to a random bilibili cdn
    parser.add_argument("--num_probes", type=int, default=20)
    parser.add_argument("--output_dir", type=str, default="sting_logs")
    parser.add_argument("--dest_port", type=int, default=80)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--maxwait", type=float, default=3.0)

    args = parser.parse_args()

    # os.makesdir(args.output_dir, exist_ok=True)
    # ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    # output_csv = os.path.join(args.output_dir, f"string_result_{ts}.csv")
    ip_addr, result = run_sting(args.ip_addr, args.num_probes, args.dest_port, args.interval, args.maxwait) 
    print(f"navigated {ip_addr}")
    print(result)


    
