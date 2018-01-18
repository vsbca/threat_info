'''This module uses Virusttotal API'''
import requests
import json

import Helper

def vt_ip(ip, api):
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    
    #vt_api="830f7ee616d1c181bf909dff1fb88a09995ed921b7ad29d2d7bebc8b8c83c77e"
    vt_api = api

    parameter = {"ip": ip, "apikey": vt_api}
    #test IP 209.90.88.140
    print("============ Virus Total Detection =============")
    r = requests.get(url,params=parameter)
   
    if r.status_code == 204:
        return 204

    if r.status_code == 200:
        data = r.json()
        if data['response_code'] == 1:
            as_owner = data.get('as_owner')
            asn = data.get('asn')
            country = data.get('country')
            if data.get('detected_communicating_samples'):
                detected_comm_samples = len(data.get('detected_communicating_samples'))
            else:
                detected_comm_samples = None
            if data.get('detected_downloaded_samples'):
                detected_down_samples = len(data.get('detected_downloaded_samples'))
            else:
                detected_down_samples = None
            if data.get('detected_referrer_samples'):
                detected_ref_samples = len(data.get('detected_referrer_samples'))
            else:
                detected_ref_samples = None
            if data.get('detected_urls'):
                detected_urls = len(data.get('detected_urls'))
            else:
                detected_urls = None
            if data.get('resolutions'):
                resolutions = data.get('resolutions')
            else:
                resolutions = None
            if data.get('undetected_communicating_samples'):
                undetected_comm_samples = len(data.get('undetected_communicating_samples'))
            else:
                undetected_comm_samples = None
            if data.get('undetected_downloaded_samples'):
                undetected_down_samples = len(data.get('undetected_downloaded_samples'))
            else:
                undetected_down_samples = None
            if data.get('undetected_referrer_samples'):
                undetected_ref_samples = len(data.get('undetected_referrer_samples'))
            else:
                undetected_ref_samples = None
            return as_owner, asn, country, detected_comm_samples, detected_down_samples, detected_ref_samples, detected_urls,\
                resolutions, undetected_comm_samples, undetected_down_samples, undetected_ref_samples
        else:
            print("Request was unsuccessful. Virustotal report: %s" % data['verbose_msg'])
    else:
        print("Something went wrong. VT status code: %s" % r.status_code)

def vt_domain(domain, api):
    url = "https://www.virustotal.com/vtapi/v2/domain/report"

    parameters = {"domain": domain, "apikey": api}
    r = requests.get(url, params=parameters)

    if r.status_code == 204:
        return 204
    if r.status_code == 200:
        try:
            data = r.json()
        except json.JSONDecodeError as e:
            print("Json decoding error: %s" % e)
            return
        if data['response_code'] == 1:
            resolutions = data.get('resolutions')
            webutation = data.get('Webutation domain info')
            opera = data.get('Opera domain info')
            if data.get('undetected_referrer_samples'):
                undetected_ref_samples = len(data.get('undetected_referrer_samples'))
            else:
                undetected_ref_samples = None
            wot = data.get('WOT domain info')
            if data.get('detected_downloaded_samples'):
                detected_down_samples = len(data.get('detected_downloaded_samples'))
            else:
                detected_down_samples = None
            if data.get('detected_referrer_samples'):
                detected_ref_samples = len(data.get('detected_referrer_samples'))
            else:
                detected_ref_samples = None
            if data.get('detected_urls'):
                detected_urls = len(data.get('detected_urls'))
            else:
                detected_urls = None
            bitdefender = data.get('BitDefender domain info')
            if data.get('detected_communicating_samples'):
                detected_comm_samples = len(data.get('detected_communicating_samples'))
            else:
                detected_comm_samples = None
            if data.get('undetected_communicating_samples'):
                undetected_comm_samples = len(data.get('undetected_communicating_samples'))
            else:
                undetected_comm_samples = None
            if data.get('undetected_downloaded_samples'):
                undetected_down_samples = len(data.get('undetected_downloaded_samples'))
            else:
                undetected_down_samples = None
            alexa = data.get('Alexa rank')
            whois = data.get('whois')
            subdomains = data.get('subdomains')
            return resolutions, webutation, opera, undetected_ref_samples, wot, detected_down_samples, detected_ref_samples,\
                       detected_urls, bitdefender, detected_comm_samples, undetected_comm_samples, undetected_down_samples, alexa, whois, subdomains
        else:
            print("Request was unsuccessful. Virustotal report: %s" % data['verbose_msg'])
    else:
        print("Something went wrong, VT status code: %s" % r.status_code)

def vt_hash(h, api):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": h, "apikey": api}
    r = requests.get(url, params=parameters, headers=Helper.user_agent())
    if r.status_code == 204:
        return 204
    if r.status_code == 200:
        data = r.json()
        if data['response_code'] == 1:
            scan_date = data['scan_date']
            results = str(data['positives']) + "/" + str(data['total'])
            details = data['scans']
            return scan_date, results, details
        else:
            print("Request was unsuccessful. Virustotal report: %s" % data['verbose_msg'])
    else:
        print("Something went wrong, VT status code: %s" % r.status_code)

def vt_url(domain, api):
    if domain:
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": "http://" + domain, "apikey": api}
        r = requests.get(url, params=parameters)
        if r.status_code == 204:
            return 204
        if r.status_code == 200:
            try:
                data = r.json()
            except json.JSONDecodeError as e:
                print("Json decoding error %s" % e)
                return
            if data['response_code'] == 1:
                scan_date = data['scan_date']
                results = str(data['positives']) + "/" + str(data['total'])
                return scan_date, results
            else:
                print("Request was unsuccesful. Virustotal report: %s" % data['verbose_msg'])
        else:
            print("Something went wrong, VT status code: %s" % r.status_code)
