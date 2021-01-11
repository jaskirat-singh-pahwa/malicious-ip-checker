import requests
from typing import Union
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 10-01-2021
 * Time: 17:52

'''

'''
API Link: https://www.dshield.org/api/#ipdetails
Documentation: https://www.dshield.org/api/#ipdetails

'''


def dshield_main(ip_address: str) -> Union[int, str]:
    url = "http://isc.sans.edu/api/ip/" + ip_address

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   api_name="DShield")

    json_response = get_processed_response(raw_response=raw_response, api_name="DShield")

    if "ip" in json_response:
        if "threatfeeds" in json_response["ip"]:
            if json_response["ip"]["maxrisk"] is not None and int(json_response["ip"]["maxrisk"]) > 0:
                risk_score = 8
            else:
                risk_score = 2

        else:
            if json_response["ip"]["maxrisk"] is not None and int(json_response["ip"]["maxrisk"]) > 0:
                risk_score = 4
            else:
                risk_score = 0

    else:
        return "No information about this IP"

    return risk_score
