import requests
from requests.auth import HTTPBasicAuth
from typing import Union
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 19-01-2021
 * Time: 17:41

'''

'''
API Link: https://app.fraudguard.io/
Documentation: https://app.fraudguard.io/
You need to register for your free trial

There is a field called threat_level which is from 0 to 10

'''


def fraud_guard_main(ip_address: str) -> Union[int, str]:
    url: str = "https://api.fraudguard.io/v2/ip/" + ip_address
    auth = HTTPBasicAuth('q78IxjXdPLlU8X6z', '9fO79XLLC5yCs3Ht')

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   auth=auth,
                                                                   api_name="Fraud Guard")

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response)
        if "risk_level" in json_response:
            risk_score = json_response["risk_level"]
            category = json_response["threat"]

            return risk_score

        else:
            return 0

    elif raw_response.status_code == 400:
        return "Your request is invalid"

    elif raw_response.status_code == 401:
        return "Your login credentials are invalid."

    elif raw_response.status_code == 429:
        return "You've exceeded the number of API requests allocated in your pricing plan"

    elif raw_response.status_code == 500:
        return "Internal server error"

    else:
        return "Some unknown exception"
