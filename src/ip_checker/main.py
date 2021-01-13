from typing import List, Union, Dict
import pandas as pd
import sys

from src.ip_checker.args import parse_args
from src.ip_checker.reader import Reader
from src.ip_checker.writer import Writer
from src.ip_checker.apis.virustotal_api import virustotal_main
from src.ip_checker.apis.threat_crowd_api import threat_crowd_main
from src.ip_checker.apis.security_rating_api import security_rating_main
from src.ip_checker.apis.abuse_ip_api import abuse_main
from src.ip_checker.apis.alien_vault_api import alien_vault_main
from src.ip_checker.apis.dshield_api import dshield_main
from src.ip_checker.apis.anti_deo_api import anti_deo_main
from src.ip_checker.apis.api_void import api_void_main
from src.ip_checker.apis.ibm_xforce_api import ibm_xforce_main


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
    abuse_ip: List[Union[str, int]] = []
    alien_vault: List[Union[str, int]] = []
    dshield: List[Union[str, int]] = []
    anti_deo: List[Union[str, int]] = []
    api_void: List[Union[str, int]] = []
    ibm_xforce: List[Union[str, int]] = []

    reader: Reader = Reader(file_path=ip_addresses_file_path)
    ip_addresses: pd.DataFrame = reader.read_csv()

    for index in range(len(ip_addresses)):
        virustotal_score: Union[int, str] = virustotal_main(ip_addresses.loc[index, "ip_address"])
        threat_crowd_score: Union[int, str] = threat_crowd_main(ip_addresses.loc[index, "ip_address"])
        security_rating_score = security_rating_main(ip_addresses.loc[index, "ip_address"])
        abuse_ip_score = abuse_main(ip_addresses.loc[index, "ip_address"])["RiskScore"]
        alien_vault_score = alien_vault_main(ip_addresses.loc[index, "ip_address"])["RiskScore"]
        dshield_score = dshield_main(ip_addresses.loc[index, "ip_address"])
        anti_deo_score = anti_deo_main(ip_addresses.loc[index, "ip_address"])["RiskScore"]

        if "RiskScore" in api_void_main(ip_addresses.loc[index, "ip_address"]):
            api_void_score = api_void_main(ip_addresses.loc[index, "ip_address"])["RiskScore"]
        else:
            api_void_score = api_void_main(ip_addresses.loc[index, "ip_address"])

        ibm_xforce_score = ibm_xforce_main(ip_addresses.loc[index, "ip_address"])

        ips.append(ip_addresses.loc[index, "ip_address"])
        virustotal.append(virustotal_score)
        threat_crowd.append(threat_crowd_score)
        security_rating.append(security_rating_score)
        abuse_ip.append(abuse_ip_score)
        alien_vault.append(alien_vault_score)
        dshield.append(dshield_score)
        anti_deo.append(anti_deo_score)
        api_void.append(api_void_score)
        ibm_xforce.append(ibm_xforce_score)

    output["Ip_address"] = ips
    output["Virustotal"] = virustotal
    output["Threat_Crowd"] = threat_crowd
    output["Security_Rating"] = security_rating
    output["Abuse_Ip"] = abuse_ip
    output["Alien_Vault"] = alien_vault
    output["DShield"] = dshield
    output["Anti_Deo"] = anti_deo
    output["Api_Void"] = api_void
    output["Ibm_Xforce"] = ibm_xforce

    return pd.DataFrame(output)


if __name__ == "__main__":
    main(sys.argv[1:])
