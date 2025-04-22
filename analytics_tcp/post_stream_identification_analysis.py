from collections import defaultdict
import pyshark, logging, argparse, os
from tqdm import tqdm
import pandas as pd

logging.basicConfig(filename="logger.out", level=logging.INFO)
logger = logging.getLogger()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--root_dir", type=str, default=".")

    args = parser.parse_args()

    captures = os.listdir(args.root_dir)


    for capture in captures:

        if capture.endswith(".csv"):
            df = pd.read_csv(os.path.join(args.root_dir, capture))
            print(df.head())
