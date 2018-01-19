import vulners 

import json

def Search_exploit(search_string):
    vul_api = vulners.Vulners()
    try:
        cve_search = vul_api.document(search_string)

        l=cve_search.get('references')

        for link in l:
            if "exploit" in link or "github" in link or "seclists" in link:
                print(link)
    except:
        print("there is no exploit/poc for this cve")
p=Search_exploit("CVE-2014-0160")
print(p)

