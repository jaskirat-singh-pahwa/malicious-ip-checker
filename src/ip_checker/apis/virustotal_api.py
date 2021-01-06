import requests
from typing import Union, Dict, List


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
    try:
        url: str = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        params: Dict[str, str] = {"apikey": "4c87da16e6533d85a56f2f2fafd14661318abf778b158fe591c689eb1050b33f", "ip": ip_address}
        response = requests.get(url, params=params)

    except requests.exceptions.HTTPError as e:
        return f"VirusTotal HTTP connection exception: {e}"
    except requests.exceptions.ConnectionError as e:
        return f"VirusTotal connection exception: {e}"
    except requests.exceptions.RequestException as e:
        return f"VirusTotal exception: {e}"

    json_response = response.json()
    ip_scores: List[int] = []

    if "detected_downloaded_samples" in json_response:
        for i in range(len(json_response["detected_downloaded_samples"])):
            ip_scores.append(json_response["detected_downloaded_samples"][i]["positives"])

    if "detected_urls" in json_response:
        for i in range(len(json_response["detected_urls"])):
            ip_scores.append(json_response["detected_urls"][i]["positives"])

    ip_threat_score: int = get_score(ip_scores)

    return ip_threat_score
