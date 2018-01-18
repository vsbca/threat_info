import requests
from cymon import Cymon

def cymon_api_call(api=None, ip=None):
    try:
        #Most of the cases Cymon doesn't need API, so intantiated the request without it
        req = Cymon()
        cymon_data = req.ip_lookup(ip)
      
        
    except requests.exceptions.HTTPError as e:
        print("Not found, Cymon not able to find: %s" % e)
        return
    
    if cymon_data:
        return('''
        Cymon report for IP %s
        =================================
        Record created: %s
        Last updated: %s
        Blacklisted by: %s
        ''' % (ip, cymon_data.get('created'), cymon_data.get('updated'), cymon_data.get('sources')))

def cymon_api_domain(api=None, domain=None):
    #Connect for domain name check
    try:
        cymon = Cymon(api)
        cymon_data = cymon.domain_lookup(domain)
        
    except requests.exceptions.HTTPError as e:
        print("Error or not found, Cymon says: %s" % e)
        return

    if cymon_data:
        return('''
        Cymon report for domain %s
        =======================
        Record created: %s
        Last updated: %s
        Blacklisted by: %s
        ''' % (domain, cymon_data.get('created'), cymon_data.get('updated'), cymon_data.get('sources')))

#p=cymon_api_call(api="6a91c1aa53efd9c8176773eaebeeb5a1493852aa",ip="103.73.224.29")
#print(p)