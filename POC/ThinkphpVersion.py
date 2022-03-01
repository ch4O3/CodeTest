# coding=utf-8
from ClassCongregation import color
import requests
import re

print("用法：http://example.com/{index.php}可选")
pathdict = [
    '?s=index2/index/index', 
    '?s=index/index/index',
    ]
    
def check(**kwargs):
    url = kwargs['url'].strip('/')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
        'Connection': 'close', 
        'Accept-Encoding': 'gzip, deflate', 
        'Accept': '*/*',}
    for path in pathdict:
        try:
            r = requests.get(url + path, headers=headers, timeout=5, verify=False)
            if (re.findall('ThinkPHP', r.text, flags=re.IGNORECASE)) or ('系统发生错误' in r.text) or ('无法载入模组' in r.text):
                try:
                    version =re.search(r'([356]\.)([012]\.)(\d{1,2})',r.text).group()
                except Exception:
                    version = '?.?.?'
                try:
                    r_title = requests.get(url, headers=headers, timeout=5, verify=False)
                    title = "".join(re.findall('<title>(.+)</title>',r_title.text))
                except Exception:
                    title = '?.?.?'
                    
                color('[+] ThinkPHP V%s | '%version + url +' | '+title, 'green')
                return 'ThinkPHP V'+version
        except Exception:
            color('[-] Request error   | ' + url + path, 'red')
            #color("[*] %s request error!"%(url + path), 'red')
            #continue
    color('[-] No ThinkPHP     | ' + url, 'red')
    return 'None'

















