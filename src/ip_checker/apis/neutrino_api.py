import requests
from typing import Union, Dict
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)

'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 18-01-2021
 * Time: 22:01

'''

'''
API Link: https://www.neutrinoapi.com/api/ip-blocklist/
Documentation: https://www.neutrinoapi.com/account/tools/?api=ip-blocklist

Check the API response on the above link

'''


def neutrino_main(ip_address: str) -> Union[int, str]:
    url: str = "https://neutrinoapi.com/ip-blocklist"

    params: Dict[str, str] = {
        'user-id': 'jaskirat96',
        'api-key': 'qfJmLeiNymWa4PmPkxkLCTmcCdRCnJNn753SaO4FzZchiUoB',
        'ip': ip_address
    }

    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=params,
                                                                   ip_address=ip_address,
                                                                   api_name="Neutrino")

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response)

        if "blocklists" in json_response:
            if len(json_response["blocklists"]) > 0:
                category = ""

                risk_score = len(json_response["blocklists"])

                for i in range(len(json_response["blocklists"])):
                    category = category + str(json_response["blocklists"][i]) + ' , '

                category = category.strip(" , ")

                return risk_score

            else:
                return 0

        else:
            return "No information about this IP"

    elif raw_response.status_code == 400:
        return "Missing or invalid parameter or daily API limit exceeded or invalid URL"

    elif raw_response.status_code == 403:
        return "Access denied"

    elif raw_response.status_code == 500:
        return "Fatal exception from the API"

    else:
        return "Some unknown exception"
