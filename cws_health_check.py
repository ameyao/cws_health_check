# SASE CWS Health Check
import json
import requests
import urllib3
import argparse
from tabulate import tabulate


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# COLOR PALETTE
HEADER = "\033[95m"
OKBLUE = "\033[94m"
OKCYAN = "\033[96m"
OKGREEN = "\033[92m"
WARNING = "\033[93m"
ENDC = "\033[0m"

keys = [
    "CWS Service Status",
    "VNI Response Time",
    "CWS DB Connection",
    "CWS Manager Service",
]
table = []


def cws_health_check(vco_url):
    cws_health_check_api_path = "https://" + vco_url + "/api/cws/v1/healthcheck"
    print(HEADER + "\n====== CWS Health Check ======" + ENDC)
    print(OKCYAN + "VCO URL: {}".format(vco_url) + ENDC)
    try:
        response = requests.get(cws_health_check_api_path)
        if response.status_code == 200 or response.status_code == 500:
            try:
                data = json.loads(response.text)
                table.append(["CWS Service Status", data["status"]])
                table.append(["VNI Response Time", data["checks"]["vni:responseTime"]["status"]])
                table.append(["CWS DB Connection", data["checks"]["database:connection"]["status"]])
                table.append(["CWS Manager Service", data["checks"]["cwsManager:responseTime"]["status"]])
                print(tabulate(table, tablefmt="fancy_grid", numalign="center"))
            except Exception as e:
                print(WARNING + f"An exception occurred: {type(e).__name__}" + ENDC)
        else:
            print(WARNING + "\tUnable to contact VCO" + ENDC)

    except Exception as e:
        print(WARNING + f"An exception occurred: {type(e).__name__}" + ENDC)


def argument_parser():
    parser = argparse.ArgumentParser(description="CWS health check")
    parser.add_argument(
        "--vco_url",
        required=False,
        type=str,
        action="store",
        default=None,
        help="Mention VCO URL for which you need to check the health of CWS service",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = argument_parser()
    cws_health_check(args.vco_url)
