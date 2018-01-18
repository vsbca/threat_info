import requests
from bs4 import BeautifulSoup


import Helper

VERSION = "1.0"
def user_agent():
    UA = {"User-Agent": "Threat Intelligence/%s" % VERSION}
    return UA



''' This below code will read file'''
def read_file(filename):
    with open(filename) as f:
        for line in f:
            yield line.strip("\n")


def get_data(url, data):
    try:
        r = requests.get(url + data, headers=Helper.user_agent())
        if r.status_code == 200:
            html_page = r.text
            return html_page
        else:
            print("Request was unsuccessful. Status code: %s" % r.status_code)
            return
    except requests.exceptions.HTTPError as e:
        print("Error: %s" % e)
        return


def ipvoid(html_page):
    try:
        soup = BeautifulSoup(html_page, "html.parser")
        data = soup.find("table")
        if data:
            blacklist_data = data.find("td", text="Blacklist Status")
            blacklist_results = blacklist_data.findNext("td").text
            last_analysis_data = data.find("td", text="Analysis Date")
            last_analysis_results = last_analysis_data.findNext("td").text
            ip_addr_data = data.find("td", text="IP Address")
            ip_addr_results = ip_addr_data.findNext("td").strong.text
            rdns_data = data.find("td", text="Reverse DNS")
            rdns_results = rdns_data.findNext("td").text
            asn_data = data.find("td", text="ASN")
            asn_results = asn_data.findNext("td").text
            asn_owner_data = data.find("td", text="ASN Owner")
            asn_owner_results = asn_owner_data.findNext("td").text.replace("&quot;", "")
            country_data = data.find("td", text="Country Code")
            country_results = country_data.findNext("td").text
            return blacklist_results, last_analysis_results, ip_addr_results, rdns_results, asn_results, asn_owner_results, country_results
        else:
            print("Not found on ipvoid")
    except AttributeError as e:
        print("Error parsing ipvoid: %s" % e)
        return


def urlvoid(html_page):
    try:
        soup = BeautifulSoup(html_page, "html.parser")
        data = soup.find("table")
        if data:
            safety_data = data.find("td", text="Safety Reputation")
            safety_results = safety_data.findNext("td").text
            last_analysis_data = data.find("td", text="Analysis Date")
            last_analysis_results = last_analysis_data.findNext("td").text
            domain_age_data = data.find("td", text="Domain 1st Registered")
            domain_age_results = domain_age_data.findNext("td").text
            country_data = data.find("td", text="Server Location")
            country_results = country_data.findNext("td").text
            alexa_data = data.find("td", text="Alexa Traffic Rank")
            alexa_results = alexa_data.findNext("td").text
            data_for_ip = soup.find("div", id="ipaddress")
            ipdata = data_for_ip.find("table")
            ip_addr_data = ipdata.find("td", text="IP Address")
            ip_addr_results = ip_addr_data.findNext("td").strong.text
            host_data = ipdata.find("td", text="Hostname")
            host_results = host_data.findNext("td").text
            asn_data = ipdata.find("td", text="ASN")
            asn_results = asn_data.findNext("td").text
            asn_owner_data = ipdata.find("td", text="ASN Owner")
            asn_owner_results = asn_owner_data.findNext("td").text.replace("&quot;", "")
            ip_country_data = ipdata.find("td", text="Country Code")
            ip_country_results = ip_country_data.findNext("td").text
            return safety_results, last_analysis_results, domain_age_results, country_results, alexa_results, ip_addr_results, host_results, asn_results, asn_owner_results, ip_country_results
        else:
            print("Not found on urlvoid")
    except AttributeError as e:
        print("Error parsing urlvoid: %s" % e)
        return
