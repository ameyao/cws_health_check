# SASE CWS Health Check
import json

import requests
import urllib3
from tabulate import tabulate
from termcolor import colored

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# COLOR PALETTE
HEADER = "\033[95m"
OKBLUE = "\033[94m"
OKCYAN = "\033[96m"
OKGREEN = "\033[92m"
WARNING = "\033[93m"
FAIL = "\033[91m"
ENDC = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

token = "Specify the API Token here"
vco_url = "Specify VCO URL here"

keys = [
    "CWS Service Status",
    "VNI Response Time",
    "CWS DB Connection",
    "CWS Manager Service",
]
table = []


def cws_health_check():
    headers = {"Authorization": f"Token {token}"}
    cws_health_check_api_path = "https://" + vco_url + "/api/cws/v1/healthcheck"
    response = requests.get(cws_health_check_api_path, headers=headers)
    if response.status_code == 200:
        print(HEADER + "\n====== CWS Health Check ======" + ENDC)
        print(OKCYAN + "VCO URL: {}".format(vco_url) + ENDC)
        data = json.loads(response.text)
        table.append(["CWS Service Status", data["status"]])
        table.append(
            ["VNI Response Time", data["checks"]["vni:responseTime"]["status"]]
        )
        table.append(
            ["CWS DB Connection", data["checks"]["database:connection"]["status"]]
        )
        table.append(
            ["CWS Manager Service", data["checks"]["cwsManager:responseTime"]["status"]]
        )
        formatted_table = [
            [colored(key, attrs=["bold"]), colored(str(value), "green")]
            for key, value in table
        ]
        print(tabulate(formatted_table, tablefmt="fancy_grid", numalign="center"))

    else:
        print(response.text)
        print(WARNING + "\tUnable to reach VCO" + ENDC)


if __name__ == "__main__":
    cws_health_check()
