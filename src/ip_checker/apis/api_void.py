import requests
from typing import Union, Dict
from src.ip_checker.helper import (get_raw_response,
                                   get_processed_response)

'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 11-01-2021
 * Time: 21:37

'''

'''
API Link: https://docs.apivoid.com
Documentation: https://www.apivoid.com/api/ip-reputation/

You need to register through email to get some free requests for this API
Here we are using IP Reputation API

'''


def api_void_main(ip_address: str) -> Union[int, str, Dict[str, Union[int, str]]]:
    url: str = "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/"
    params: Dict[str, str] = {
        "key": "2c428407b6b8a66b05ef95c20f6966bbd721b35c",
        "ip": ip_address
    }
    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=None,
                                                                   params=params,
                                                                   ip_address=ip_address,
                                                                   api_name="Api Void")
    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response=raw_response)

        if not ("error" in json_response):
            category = ""
            if json_response["data"]["report"]["blacklists"]["detections"] > 35:
                risk_score = 8
            elif json_response["data"]["report"]["blacklists"]["detections"] > 20:
                risk_score = 5
            elif json_response["data"]["report"]["blacklists"]["detections"] > 0:
                risk_score = 2
            else:
                risk_score = 0

            if json_response["data"]["report"]["anonymity"]["is_proxy"] is True:
                category = category + "Proxy" + " , "

            if json_response["data"]["report"]["anonymity"]["is_webproxy"] is True:
                category = category + "Web Proxy" + " , "

            if json_response["data"]["report"]["anonymity"]["is_vpn"] is True:
                category = category + "Vpn" + " , "

            if json_response["data"]["report"]["anonymity"]["is_hosting"] is True:
                category = category + "Hosting" + " , "

            if json_response["data"]["report"]["anonymity"]["is_tor"] is True:
                category = category + "Tor" + " , "

            category = category.strip(" , ")

            return {"IpAddress": ip_address, "RiskScore": risk_score, "Category": category}

        else:
            return json_response["error"]

    else:
        return "The status code is not 200"


if __name__ == "__main__":
    print(api_void_main("192.268.10.1"))
