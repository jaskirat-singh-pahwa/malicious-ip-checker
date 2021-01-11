import requests
from typing import Union, Dict
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)

'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 05-01-2021
 * Time: 14:47

'''

'''
The votes field will help us to decccide whether a given ipAddress is malicious or not.
If the value of votes is:
    -1: Most users have votes this as malicious.
    0: Equal Numbers of users have voted this malicious.
    1: Most users have voted this not malicious.

'''


def threat_crowd_main(ip_address: str) -> Union[str, int]:
    url: str = "http://www.threatcrowd.org/searchApi/v2/ip/report/"
    params: Dict[str, str] = {"ip": ip_address}
    raw_response: requests.Response = get_raw_response(url=url,
                                                       headers=None,
                                                       params=params,
                                                       ip_address=ip_address,
                                                       api_name="Threat Crowd")
    risk_score: int = 0

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response=raw_response)

        if "votes" in json_response:
            if json_response["votes"] == -1:
                risk_score = 10
            elif json_response["votes"] == 0:
                risk_score = 5
            else:
                risk_score = 0

        return risk_score

    elif raw_response.status_code == 429:
        return "Free trial is over"

    elif raw_response.status_code == 504:
        return "No information about this IP"

    else:
        return "Some unknown exception"
