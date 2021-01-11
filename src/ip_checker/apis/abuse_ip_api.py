import requests
from typing import Union, Dict, List
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)

'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 07-01-2021
 * Time: 11:15

'''

'''
API Link: https://www.abuseipdb.com/api.html
Documentation: https://docs.abuseipdb.com/#check-endpoint

This API gives you abuseConfidenceScore as a parameter to take action against any endpoint.
This score ranges from 0 to 100, the more it is close to 100, the more malign it would be.

'''


def get_attack_categories() -> Dict[int, str]:
    return {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }


def abuse_main(ip_address: str) -> Union[Dict[str, Union[int, str, List[str]]], str, int]:
    ip_categories: List[str] = []

    marked_categories: Dict[int, str] = get_attack_categories()

    url: str = "https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip_address,
              'key': '124edb2bed9ea9c6500f6d66945cefda615036d8cf757a4e0a55ffe27caf09a5a702be4e578dbe7f',
              'verbose': True,
              'maxAgeInDays': 365}

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=params,
                                                                   ip_address=ip_address,
                                                                   api_name="Abuse IP")

    json_response = get_processed_response(raw_response=raw_response)
    if raw_response.status_code == 200:
        category: str = ""

        if len(json_response) > 0:
            risk_score: int = int(json_response["data"]["abuseConfidenceScore"])

            if "reports" in json_response["data"]:
                for i in range(len(json_response["data"]["reports"])):
                    ip_categories.append(json_response["data"]["reports"][i]["categories"])

                flat_list = []
                if len(ip_categories) > 0:
                    for sublist in ip_categories:
                        for i in sublist:
                            flat_list.append(i)

                    flat_list = set(flat_list)

                    for i in flat_list:
                        category = category + marked_categories[int(i)] + " , "
                    category = category.strip(" , ")

                return {"IpAddress": str(ip_address), "RiskScore": risk_score, "Category": category}

            else:
                return {"IpAddress": str(ip_address), "RiskScore": risk_score, "Category": category}

        else:
            risk_score = 0
            category = ""
            return {"IpAddress": str(ip_address), "RiskScore": risk_score, "Category": category}

    elif json_response[0]["status"] == str(429):
        return "You have exceeded daily limit"

    else:
        return "Some unknown exception"
