import requests
from typing import Union, List
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)

'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 13-01-2021
 * Time: 21:43

'''

'''
API Link: https://api.xforce.ibmcloud.com/doc/#IP_Reputation_get_ipr_history_ip
Documentation: https://api.xforce.ibmcloud.com/doc/#IP_Reputation_get_ipr_history_ip

200 status code: Ip report exists and there we have score from which we can check whether the
given IP is malicious or not.
Higher the score, more malicious the IP is

402 status code: Monthly quota is over
403 status code: Access denied
404 status code: Not found

'''


def ibm_xforce_main(ip_address: str) -> Union[int, str]:
    url: str = "https://api.xforce.ibmcloud.com/ipr/history/" + ip_address
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic YTlhOTFhYWYtNjk1NC00NDhjLTllNDEtOGU1ZDMzNmUwM2MwOmQ1ODY1ZTE5LTk2NzAtNDExMi04NTA2LWE2MzcyZWI1NTg2ZA=='
    }

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=headers,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   api_name="Abuse IP")

    if raw_response.status_code == 200:
        ip_scores: List[int] = []
        json_response = get_processed_response(raw_response=raw_response)

        if "history" in json_response:
            for i in range(len(json_response["history"])):
                ip_scores.append(json_response["history"][i]["score"])

            risk_score = max(ip_scores)

        else:
            risk_score = 0

        return risk_score

    elif raw_response.status_code == 402:
        return "Monthly free trial is over"

    elif raw_response.status_code == 403:
        return "API access denied, check authorization key"

    elif raw_response.status_code == 404:
        return "No history found for this IP"

    else:
        return "Some unknown exception"
