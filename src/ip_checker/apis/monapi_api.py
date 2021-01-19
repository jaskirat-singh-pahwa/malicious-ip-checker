import requests
from typing import Union
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 15-01-2021
 * Time: 13:26

'''

'''
API Link: https://www.monapi.io
Documentation: https://www.monapi.io

You you will get a calculated threat score for that IP between 1 and 100. 
A higher score means more potential threat.

Also there is one more field called threat_level which is either low, medium or high
Here I will be using threat_level field.

'''


def monapi_main(ip_address: str) -> Union[int, str]:
    url = "https://api.monapi.io/v1/ip/" + ip_address

    headers = {
        'accept': "application/json",
        'authorization': "00448aed801b8de1427501981d01e696182fe333"
    }

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=headers,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   api_name="Monapi")

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response)

        if "threat_level" in json_response:
            if json_response["threat_level"] == "low":
                risk_score = 2

            elif json_response["threat_level"] == "medium":
                risk_score = 5

            else:
                risk_score = 8

        else:
            risk_score = 0

        return risk_score

    elif raw_response.status_code == 400:
        return "Your request is invalid"

    elif raw_response.status_code == 401:
        return "Unauthorized -- Your API key is wrong"

    elif raw_response.status_code == 404:
        return "There is no information about this IP"

    elif raw_response.status_code == 500:
        return "Internal server error"

    else:
        return "Some unknown exception"
