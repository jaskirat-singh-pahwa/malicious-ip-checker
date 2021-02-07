from typing import List
import pandas as pd
import sys
import time

from src.ip_checker.args import parse_args
from src.ip_checker.writer import Writer
from src.ip_checker.thread_operations import run_operations


def main(argv: List) -> None:
    start = time.time()
    args = parse_args(argv)
    ip_addresses_file_path: str = args["ip_addresses"]
    output_file_path: str = args["output_path"]
    ip_address_with_scores: pd.DataFrame = run_operations(ip_addresses_file_path=ip_addresses_file_path)

    writer: Writer = Writer(df=ip_address_with_scores, write_path=output_file_path)
    writer.write_to_csv()
    end = time.time()

    print(f"Total time taken by project: {end - start}")


if __name__ == "__main__":
    main(sys.argv[1:])
