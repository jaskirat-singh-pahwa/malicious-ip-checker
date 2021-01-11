import requests
from typing import Union, Dict, List
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 07-01-2021
 * Time: 22:52

'''

'''
API Link: https://otx.alienvault.com/api
Check docs section in the above link

Documentation: https://github.com/AlienVault-OTX/OTX-Python-SDK
Also, check additional examples at the end of GitHub link.

'''


def alien_vault_main(ip_address: str) -> Union[Dict[str, Union[str, int, List[str]]], str, int]:

    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip_address + "/reputation"
    headers: Dict[str, str] = {
        'x-otx-api-key': "edc898b247fc1ad5f03f193106b38e02bd66b7d62d3b73e22fa9d2ebbcbf7dcb"
    }
    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=headers,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   api_name="Alien Vault")

    categories: List[str] = []
    threat_score = 0

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response=raw_response)
        appended_category: str = ""

        if json_response["reputation"] is not None:
            threat_score = json_response["reputation"]["threat_score"]
            response_category = json_response["reputation"]["counts"]
            for category in response_category:
                categories.append(category)

            unique_categories = set(categories)

            for category in unique_categories:
                appended_category = appended_category + str(category) + " , "

            appended_category = appended_category.strip(" , ")

            return {"Ip_Address": str(ip_address), "RiskScore": threat_score, "Category": appended_category}

        else:
            return {"Ip_Address": str(ip_address), "RiskScore": threat_score, "Category": appended_category}

    elif raw_response.status_code == 404:
        return "No information about this IP"
    else:
        return "Some unknown exception"
