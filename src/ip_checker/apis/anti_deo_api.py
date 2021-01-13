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
API Link: https://www.antideo.com/documentation/
Documentation: https://www.antideo.com/documentation/

Sample response:
"health": {
        "toxic": false,
        "proxy": false,
        "spam": false
    }
    
If its toxic then score is score + 5,
if it is proxy or spam then score is score + 2.5

'''


def anti_deo_main(ip_address: str) -> Union[float, str, Dict[str, Union[int, str]]]:
    url: str = "https://api.antideo.com/ip/health/" + ip_address
    headers: Dict[str, str] = {
        "apiKey": "4b6181c362663e8d4f548a9d5ae85989"
    }
    raw_response: Union[requests.Response, str] = get_raw_response(url=url,
                                                                   headers=headers,
                                                                   params=None,
                                                                   ip_address=ip_address,
                                                                   api_name="Anti Deo")

    risk_score = 0.0
    category = ""

    if raw_response.status_code == 200:
        json_response = get_processed_response(raw_response)
        for i in json_response["health"]:
            if json_response["health"][i] is not False:
                category = category + str(i) + " , "
                
                if i == "toxic":
                    risk_score += 5.0
                else:
                    risk_score += 2.5
            
            else:
                risk_score += 0.0
        
        category = category.strip(" , ")

        return {"IpAddress": ip_address, "RiskScore": round(risk_score), "Category": category}

    elif raw_response.status_code == 429:
        return "Free trial is over"

    else:
        return "Some unknown exception"
