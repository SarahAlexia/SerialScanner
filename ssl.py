import requests
from bs4 import BeautifulSoup as bs
from argparse import ArgumentParser
import json
from pprint import pprint

# Setting up argument parser
parser = ArgumentParser(description="SSL Searching through Serial")

# Define optional arguments for serial number and hostname
parser.add_argument("-S", "--serial", required=False, dest="serial", help="Input the Serial Number")
parser.add_argument("-H", "--host", required=False, dest="host", help="Input the Host")

# Parse link from html text
def parse_link(rss_text):
    bs_var = bs(rss_text, "html.parser")
    for td in bs_var.find_all("td"):
        if td.find("a"):
            if "id" in td.find("a")["href"]:
                return f'https://crt.sh/{td.find("a")["href"]}'

# Get certificate information from hostname
def get_cert_from_name(name):
    url_ = f"https://ssl-checker.io/api/v1/check/{name}"
    return json.loads(requests.get(url_).text)

# Clean up hostname extracted from link
def clean_name(href):
    bs_var = bs(requests.get(f"{href}").text.replace("&nbsp;", ""), "html.parser")
    text_elements = bs_var.find_all(class_='text')
    for element in text_elements:
        if "commonName" in element.get_text():
            common_name = element.get_text().split("=")[-1]
            common_name = common_name.split("Subject")[0]
            common_name.strip()
            if common_name.startswith("*."):
                common_name = common_name[2:]
            return common_name

# Get certificate information from serial number
def get_cert_name_from_serial(serial):
    url_ = f"https://crt.sh/?serial={return_serial_hex(serial)}"
    href = parse_link(requests.get(url=url_).text)
    common_name = clean_name(href)
    cert = get_cert_from_name(common_name)
    return cert

# Return hexadecimal serial number
def return_serial_hex(serial):
    try:
        if type(int(serial, 10)) == int:
            return hex(int(serial)).replace("0x", "")
    except ValueError:
        return serial


if __name__ == "__main__":
    args = parser.parse_args()
    
    # If the serial number is provided, fetch and print the certificate information
    if args.serial:
        pprint(get_cert_name_from_serial(args.serial))
    
    # If the serial number is provided, fetch and print the certificate information   
    elif args.host:
        pprint(get_cert_from_name(args.host))
    
    # If no serial number or hostname is provided, print "None Selected"
    else:
        print("None Selected")
    print("exiting")
