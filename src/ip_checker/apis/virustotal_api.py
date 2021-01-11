import requests
from typing import Union, Dict, List
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)

'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 04-01-2021
 * Time: 13:08

'''

'''
API Link: https://developers.virustotal.com/reference#getting-started

detected_urls: URLs at this IP address that have at least 1 detection on a URL scan
detected_downloaded_samples: Files that have been downloaded from this IP address with at least one AV detection

'''


def get_score(ip_scores: List[int]) -> int:
    average_threat_score: int = 0
    if (len(ip_scores) > 0) and (max(ip_scores) > 0):
        average_threat_score = round(sum(ip_scores) / len(ip_scores))

        if average_threat_score > 10:
            average_threat_score = 10

    return average_threat_score


def virustotal_main(ip_address: str) -> Union[str, int]:
    url: str = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    params: Dict[str, str] = {
        "apikey": "4c87da16e6533d85a56f2f2fafd14661318abf778b158fe591c689eb1050b33f",
        "ip": ip_address
    }
    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=params,
                                                                   ip_address=ip_address,
                                                                   api_name="Virus Total")

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response=raw_response)
        ip_scores: List[int] = []

        if "detected_downloaded_samples" in json_response:
            for i in range(len(json_response["detected_downloaded_samples"])):
                ip_scores.append(json_response["detected_downloaded_samples"][i]["positives"])

        if "detected_urls" in json_response:
            for i in range(len(json_response["detected_urls"])):
                ip_scores.append(json_response["detected_urls"][i]["positives"])

        ip_threat_score: int = get_score(ip_scores)

        return ip_threat_score

    else:
        return "Some unknown exception"
