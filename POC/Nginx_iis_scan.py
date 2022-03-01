#!/usr/bin/python
# -*- coding: UTF-8 -*-
import requests
import urllib3
import threading
import queue
import sys,getopt
sys.path.append('../')
from ClassCongregation import _urlparse

error=20  #误差值（5~10），此参数不用修改,已最优。
urllib3.disable_warnings()

def Nginx_iis_scan(url):
    try:
        path = '/.php'
        path2 = '/.232index'#异常测试时需要，能降低防止误报
        res=requests.get(url=url+path,verify=False,timeout=5)
        count=len(res.text)
        if res.status_code==200:#判断响应值
            res2 = requests.get(url=url + path2, verify=False, timeout=5)
            count2=len(res2.text)
            sum=count-count2
            if error>=abs(sum):#获取绝对值，计算误差。
                print(url + path2 + ' No Loophole')
            else:
                print(url+' 确定存在解析漏洞')
                return True
        else:
            print(url+path+' '+str(res.status_code))
    except Exception as e:
        print(url,str(e))

print('[*]请输入目标服务器上存在的静态资源文件链接,如 http://www.baidu.com/robots.txt')
def check(**kwargs):
    Nginx_iis_scan(kwargs['url'])

if __name__ == "__main__":
    Nginx_iis_scan(_urlparse("http://baidu.com/123.php"))
    print('task complete~~~~~~~~~~ 完了')



