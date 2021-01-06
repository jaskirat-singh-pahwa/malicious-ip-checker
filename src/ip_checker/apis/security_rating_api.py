import requests
import json
from typing import Union


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 05-01-2021
 * Time: 21:08

'''

'''
THIS API REQUIRES SUBSCRIPTION

This API is not properly tested because its paid, please verify the code.

GitHub Link: https://github.com/balgan/ratemyip-openframework/blob/master/ip-score.md
API Link: https://rapidapi.com/binaryedge/api/securityratings?endpoint=5a9d4824e4b04378c0c99abc
It gives score between 0 to 100,
The higher the score, the higher the vulnerability / exposure level
'''


def security_rating_main(ip_address: str) -> Union[str, int]:
    try:
        url = "https://binaryedge-securityratings-v1.p.rapidapi.com/score/ip"
        querystring = {"target": ip_address}
        headers = {
            'x-rapidapi-key': "fa8a97daacmshd6ed3316ed17476p1957b4jsn6bd3c56557db",
            'x-rapidapi-host': "binaryedge-securityratings-v1.p.rapidapi.com"
        }

        raw_response = requests.request("GET", url, headers=headers, params=querystring)

    except requests.exceptions.HTTPError as e:
        return f"Security Rating HTTP exceptionn: {e}"
    except requests.exceptions.ConnectionError as e:
        return f"Security Rating connection exception: {e}"
    except requests.exceptions.RequestException as e:
        return f"Security Rating exception : {e}"

    respose = raw_response.text
    json_response = json.loads(respose)

    if "normalized_ip_score" in json_response:
        return round(json_response["normalized_ip_score"] / 10)
    else:
        return json_response["message"]


'''
If score is 22.9 then it will return round(22.9 / 10) which is 2 as risk score

'''