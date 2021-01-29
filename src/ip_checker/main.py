from typing import List, Union, Dict
import pandas as pd
import sys
import time
from threading import Thread

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
from src.ip_checker.apis.monapi_api import monapi_main
from src.ip_checker.apis.ip_reputation import ip_reputation_main
from src.ip_checker.apis.neutrino_api import neutrino_main
from src.ip_checker.apis.fraud_guard_api import fraud_guard_main
from src.ip_checker.apis.hetrix_tools_api import hetrix_tools_main


def main(argv: List) -> None:
    start = time.time()
    args = parse_args(argv)
    ip_addresses_file_path: str = args["ip_addresses"]
    output_file_path: str = args["output_path"]
    ip_address_with_scores: pd.DataFrame = run_main(ip_addresses_file_path=ip_addresses_file_path)

    writer: Writer = Writer(df=ip_address_with_scores, write_path=output_file_path)
    writer.write_to_csv()
    end = time.time()

    print(f"Total time taken by project: {end - start}")


def run_main(ip_addresses_file_path: str) -> pd.DataFrame:
    threads = list()

    output: Dict[str, List[Union[str, int]]] = {}
    ips: List[str] = []
    virustotal: List[Union[int, str]] = []
    threat_crowd: List[Union[int, str]] = []
    security_rating: List[Union[int, str]] = []
    abuse_ip: List[Union[int, str]] = []
    alien_vault: List[Union[int, str]] = []
    dshield: List[Union[int, str]] = []
    anti_deo: List[Union[int, str]] = []
    api_void: List[Union[int, str]] = []
    ibm_xforce: List[Union[int, str]] = []
    monapi: List[Union[int, str]] = []
    ip_reputation: List[Union[int, str]] = []
    neutrino: List[Union[int, str]] = []
    fraud_guard: List[Union[int, str]] = []
    hetrix_tools: List[Union[int, str]] = []

    reader: Reader = Reader(file_path=ip_addresses_file_path)
    ip_addresses: pd.DataFrame = reader.read_csv()

    for index in range(len(ip_addresses)):

        ips.append(ip_addresses.loc[index, "ip_address"])

        virustotal_thread = Thread(
            target=lambda lst, arg: lst.append(virustotal_main(arg)),
            args=(virustotal, ip_addresses.loc[index, "ip_address"])
        )
        virustotal_thread.start()

        threat_crowd_thread = Thread(
            target=lambda lst, arg: lst.append(threat_crowd_main(arg)),
            args=(threat_crowd, ip_addresses.loc[index, "ip_address"])
        )
        threat_crowd_thread.start()

        security_rating_thread = Thread(
            target=lambda lst, arg: lst.append(security_rating_main(arg)),
            args=(security_rating, ip_addresses.loc[index, "ip_address"])
        )
        security_rating_thread.start()

        abuse_ip_thread = Thread(
            target=lambda lst, arg: lst.append(abuse_main(arg)["RiskScore"]),
            args=(abuse_ip, ip_addresses.loc[index, "ip_address"])
        )
        abuse_ip_thread.start()

        alien_vault_thread = Thread(
            target=lambda lst, arg: lst.append(alien_vault_main(arg)["RiskScore"]),
            args=(alien_vault, ip_addresses.loc[index, "ip_address"])
        )
        alien_vault_thread.start()

        dshield_thread = Thread(
            target=lambda lst, arg: lst.append(dshield_main(arg)),
            args=(dshield, ip_addresses.loc[index, "ip_address"])
        )
        dshield_thread.start()

        anti_deo_thread = Thread(
            target=lambda lst, arg: lst.append(anti_deo_main(arg)["RiskScore"]),
            args=(anti_deo, ip_addresses.loc[index, "ip_address"])
        )
        anti_deo_thread.start()

        # if "RiskScore" in api_void_main(ip_addresses.loc[index, "ip_address"]):
        #     api_void_thread = Thread(
        #         target=lambda lst, arg: lst.append(api_void_main(arg)["RiskScore"]),
        #         args=(api_void, ip_addresses.loc[index, "ip_address"])
        #     )
        #     api_void_thread.start()
        # else:
        #     api_void_thread = Thread(
        #         target=lambda lst, arg: lst.append(api_void_main(arg)["RiskScore"]),
        #         args=(api_void, ip_addresses.loc[index, "ip_address"])
        #     )
        #     api_void_thread.start()

        ibm_xforce_thread = Thread(
            target=lambda lst, arg: lst.append(ibm_xforce_main(arg)),
            args=(ibm_xforce, ip_addresses.loc[index, "ip_address"])
        )
        ibm_xforce_thread.start()

        monapi_thread = Thread(
            target=lambda lst, arg: lst.append(monapi_main(arg)),
            args=(monapi, ip_addresses.loc[index, "ip_address"])
        )
        monapi_thread.start()

        ip_reputation_thread = Thread(
            target=lambda lst, arg: lst.append(ip_reputation_main(arg)),
            args=(ip_reputation, ip_addresses.loc[index, "ip_address"])
        )
        ip_reputation_thread.start()

        neutrino_thread = Thread(
            target=lambda lst, arg: lst.append(neutrino_main(arg)),
            args=(neutrino, ip_addresses.loc[index, "ip_address"])
        )
        neutrino_thread.start()

        fraud_guard_thread = Thread(
            target=lambda lst, arg: lst.append(fraud_guard_main(arg)),
            args=(fraud_guard, ip_addresses.loc[index, "ip_address"])
        )
        fraud_guard_thread.start()

        hetrix_tools_thread = Thread(
            target=lambda lst, arg: lst.append(hetrix_tools_main(arg)),
            args=(hetrix_tools, ip_addresses.loc[index, "ip_address"])
        )
        hetrix_tools_thread.start()

        threads.append(virustotal_thread)
        threads.append(threat_crowd_thread)
        threads.append(security_rating_thread)
        threads.append(abuse_ip_thread)
        threads.append(alien_vault_thread)
        threads.append(dshield_thread)
        threads.append(anti_deo_thread)
        # threads.append(api_void_thread)
        threads.append(ibm_xforce_thread)
        threads.append(monapi_thread)
        threads.append(ip_reputation_thread)
        threads.append(neutrino_thread)
        threads.append(fraud_guard_thread)
        threads.append(hetrix_tools_thread)

    for thread in threads:
        thread.join()

    output["Ip_address"] = ips
    output["Virustotal"] = virustotal
    output["Threat_Crowd"] = threat_crowd
    output["Security_Rating"] = security_rating
    output["Abuse_Ip"] = abuse_ip
    output["Alien_Vault"] = alien_vault
    output["DShield"] = dshield
    output["Anti_Deo"] = anti_deo
    # output["Api_Void"] = api_void
    output["Ibm_Xforce"] = ibm_xforce
    output["Monapi"] = monapi
    output["IP_Reputation"] = ip_reputation
    output["Neutrino"] = neutrino
    output["Fraud_Guard"] = fraud_guard
    output["Hetrix_Tools"] = hetrix_tools

    return pd.DataFrame(output)


if __name__ == "__main__":
    main(sys.argv[1:])
