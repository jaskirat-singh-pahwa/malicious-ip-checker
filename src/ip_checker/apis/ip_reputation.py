import requests
from typing import Union, Dict
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 18-01-2021
 * Time: 17:30

'''

'''
API Link: https://rapidapi.com/Top-Rated/api/ip-reputation-geoip-and-detect-vpn/endpoints
Documentation: https://rapidapi.com/Top-Rated/api/ip-reputation-geoip-and-detect-vpn/endpoints

You you will get risk for that IP between 1 and 100. 
A higher score means more potential threat.

Also there is one more field called risk_level which is either low, medium or high
Here I will be using risk_level field

TO USE FREE PLAN OF THIS IP YOU NEED TO SUBSCRIBE

'''


def ip_reputation_main(ip_address: str) -> Union[int, str]:

    url: str = "https://ip-reputation-geoip-and-detect-vpn.p.rapidapi.com/"
    params: Dict[str, str] = {"ip": "185.65.135.230"}
    headers: Dict[str, str] = {
        'x-rapidapi-key': "fa8a97daacmshd6ed3316ed17476p1957b4jsn6bd3c56557db",
        'x-rapidapi-host': "ip-reputation-geoip-and-detect-vpn.p.rapidapi.com"
    }

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=headers,
                                                                   params=params,
                                                                   ip_address=ip_address,
                                                                   api_name="Monapi")

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response)

        if "risk_level" in json_response:
            if json_response["risk_level"] == "low":
                risk_score = 2

            elif json_response["risk_level"] == "medium":
                risk_score = 5

            else:
                risk_score = 8

        else:
            risk_score = 0

        return risk_score

    elif raw_response.status_code == 429:
        return "Your daily limit is exceeded"

    else:
        return "Some unknown exception"
