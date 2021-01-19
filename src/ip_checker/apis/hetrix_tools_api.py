import requests
from typing import Union
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 19-01-2021
 * Time: 23:13

'''

'''
API Link: https://docs.hetrixtools.com/
Documentation: https://docs.hetrixtools.com/

'''


def hetrix_tools_main(ip_address: str) -> Union[int, str]:
    url: str = "https://api.hetrixtools.com/v2/28ed32b672bc5728ee675f35b3c9758d/blacklist-check/ipv4/" + ip_address + "/"

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   api_name="Hetrix")

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response)
        if "blacklisted_count" in json_response:
            if json_response["blacklisted_count"] > 0:
                risk_score = 8
                category = "blacklisted"

            else:
                risk_score = 0
                category = "Not blacklisted"

            return risk_score

        else:
            return "There is no information about this IP"
