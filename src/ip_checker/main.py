from typing import List
import pandas as pd
import sys
# sys.path.append("/malicious-ip-checker/src/")

from src.ip_checker.args import parse_args
from src.ip_checker.reader import Reader
from src.ip_checker.writer import Writer


def main(argv: List) -> None:
    args = parse_args(argv)
    ip_addresses_file_path: str = args["ip_addresses"]
    output_file_path: str = args["output_path"]
    ip_address_with_scores: pd.DataFrame = run_main(ip_addresses_file_path=ip_addresses_file_path)

    writer: Writer = Writer(df=ip_address_with_scores, write_path=output_file_path)
    writer.write_to_csv()


def run_main(ip_addresses_file_path: str) -> pd.DataFrame:
    reader: Reader = Reader(file_path=ip_addresses_file_path)
    ip_addresses: pd.DataFrame = reader.read_csv()
    print(ip_addresses.head())

    return ip_addresses


if __name__ == "__main__":
    main(sys.argv[1:])
