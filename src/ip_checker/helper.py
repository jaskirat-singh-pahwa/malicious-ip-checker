import requests
import json
from typing import Dict, Union
import xmltodict


def get_raw_response(
        url: str,
        headers: Union[Dict[str, str], None],
        params: Union[Dict[str, str], None],
        ip_address: str,
        api_name: str
        ) -> Union[requests.Response, str]:

    try:
        return requests.request(method="GET", url=url, headers=headers, params=params)

    except requests.exceptions.HTTPError as e:
        return f"{api_name} HTTP connection exception for {ip_address} ip address: {e}"
    except requests.exceptions.ConnectionError as e:
        return f"{api_name} connection exception for {ip_address} ip address: {e}"
    except requests.exceptions.RequestException as e:
        return f"{api_name} exception for {ip_address} ip address: {e}"


def get_processed_response(raw_response: requests.Response, api_name=None) -> json:
    if api_name == "DShield":
        return json.loads(json.dumps(xmltodict.parse(raw_response.text)))
    else:
        return json.loads(raw_response.text)
