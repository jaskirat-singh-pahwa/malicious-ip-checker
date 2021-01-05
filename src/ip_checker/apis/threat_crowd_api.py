import requests
import json
from typing import Union


'''
 * Author: JASKIRAT
 * Version: 1.0
 * Date: 05-01-2021
 * Time: 14:47

'''

'''
The votes field will help us to decccide whether a given ipAddress is malicious or not.
If the value of votes is:
    -1: Most users have votes this as malicious.
    0: Equal Numbers of users have voted this malicious.
    1: Most users have voted this not malicious.

'''


def threat_crowd_main(ip_address: str) -> Union[str, int]:
    try:
        raw_response = requests.get("http://www.threatcrowd.org/searchApi/v2/ip/report/", params={"ip": ip_address})
        response: str = raw_response.text

    except requests.exceptions.HTTPError as e:
        return f"Threat Crowd HTTP connectionne exceptionn: {e}"
    except requests.exceptions.ConnectionError as e:
        return f"Threat Crowd Connection EXCEPTION: {e}"
    except requests.exceptions.RequestException as e:
        return f"Threat Crowd EXCEPTION : {e}"

    risk_score: int = 0

    if raw_response.status_code == 200:
        json_response = json.loads(response)

        if "votes" in json_response:
            if json_response["votes"] == -1:
                risk_score = 10
            elif json_response["votes"] == 0:
                risk_score = 5
            else:
                risk_score = 0

        return risk_score

    elif raw_response.status_code == 429:
        return "Free trial is over"

    else:
        return "Some unnknown exception"

