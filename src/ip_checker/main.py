from typing import List, Union, Dict
import pandas as pd
import sys

from src.ip_checker.args import parse_args
from src.ip_checker.reader import Reader
from src.ip_checker.writer import Writer
from src.ip_checker.apis.virustotal_api import virustotal_main
from src.ip_checker.apis.threat_crowd_api import threat_crowd_main
from src.ip_checker.apis.security_rating_api import security_rating_main


def main(argv: List) -> None:
    args = parse_args(argv)
    ip_addresses_file_path: str = args["ip_addresses"]
    output_file_path: str = args["output_path"]
    ip_address_with_scores: pd.DataFrame = run_main(ip_addresses_file_path=ip_addresses_file_path)

    writer: Writer = Writer(df=ip_address_with_scores, write_path=output_file_path)
    writer.write_to_csv()


def run_main(ip_addresses_file_path: str) -> pd.DataFrame:
    output: Dict[str, List[Union[str, int]]] = {}
    ips: List[str] = []
    virustotal: List[Union[str, int]] = []
    threat_crowd: List[Union[str, int]] = []
    security_rating: List[Union[str, int]] = []

    reader: Reader = Reader(file_path=ip_addresses_file_path)
    ip_addresses: pd.DataFrame = reader.read_csv()

    for index in range(len(ip_addresses)):
        virustotal_score: Union[int, str] = virustotal_main(ip_addresses.loc[index, "ip_address"])
        threat_crowd_score: Union[int, str] = threat_crowd_main(ip_addresses.loc[index, "ip_address"])
        security_rating_score = security_rating_main(ip_addresses.loc[index, "ip_address"])

        ips.append(ip_addresses.loc[index, "ip_address"])
        virustotal.append(virustotal_score)
        threat_crowd.append(threat_crowd_score)
        security_rating.append(security_rating_score)

    output["Ip_address"] = ips
    output["Virustotal"] = virustotal
    output["Threat_Crowd"] = threat_crowd
    output["Security_Rating"] = security_rating

    return pd.DataFrame(output)


if __name__ == "__main__":
    main(sys.argv[1:])
