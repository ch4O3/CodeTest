#!/usr/bin/env python
# coding=utf-8
from plugins.thinkphp_checkcode_time_sqli import thinkphp_checkcode_time_sqli_verify
from plugins.thinkphp_construct_code_exec import thinkphp_construct_code_exec_verify
from plugins.thinkphp_construct_debug_rce import thinkphp_construct_debug_rce_verify
from plugins.thinkphp_debug_index_ids_sqli import thinkphp_debug_index_ids_sqli_verify
from plugins.thinkphp_driver_display_rce import thinkphp_driver_display_rce_verify
from plugins.thinkphp_index_construct_rce import thinkphp_index_construct_rce_verify
from plugins.thinkphp_index_showid_rce import thinkphp_index_showid_rce_verify
from plugins.thinkphp_invoke_func_code_exec import thinkphp_invoke_func_code_exec_verify
from plugins.thinkphp_lite_code_exec import thinkphp_lite_code_exec_verify
from plugins.thinkphp_method_filter_code_exec import thinkphp_method_filter_code_exec_verify
from plugins.thinkphp_multi_sql_leak import thinkphp_multi_sql_leak_verify
from plugins.thinkphp_pay_orderid_sqli import thinkphp_pay_orderid_sqli_verify
from plugins.thinkphp_request_input_rce import thinkphp_request_input_rce_verify
from plugins.thinkphp_view_recent_xff_sqli import thinkphp_view_recent_xff_sqli_verify
import time,requests
print('''
 ___________                    
|_   _| ___ \                   
  | | | |_/ /__  ___ __ _ _ __  
  | | |  __/ __|/ __/ _` | '_ \ 
  | | | |  \__ \ (_| (_| | | | |
  \_/ \_|  |___/\___\__,_|_| |_|          
                code by Lucifer
''')
print("用法：http://example.com/{index.php}不需要index.php")
def check(**kwargs):
  url = kwargs['url']
  try:
    s = requests.session()
    s.keep_alive = False
    thinkphp_checkcode_time_sqli_verify(url)
    time.sleep(0.5)
    thinkphp_construct_code_exec_verify(url)
    time.sleep(0.5)
    thinkphp_construct_debug_rce_verify(url)
    time.sleep(0.5)
    thinkphp_debug_index_ids_sqli_verify(url)
    time.sleep(0.5)
    thinkphp_driver_display_rce_verify(url)
    time.sleep(0.5)
    thinkphp_index_construct_rce_verify(url)
    time.sleep(0.5)
    thinkphp_index_showid_rce_verify(url)
    time.sleep(0.5)
    thinkphp_invoke_func_code_exec_verify(url)
    time.sleep(0.5)
    thinkphp_lite_code_exec_verify(url)
    time.sleep(0.5)
    thinkphp_method_filter_code_exec_verify(url)
    time.sleep(0.5)
    thinkphp_multi_sql_leak_verify(url)
    time.sleep(0.5)
    thinkphp_pay_orderid_sqli_verify(url)
    time.sleep(0.5)
    thinkphp_request_input_rce_verify(url)
    time.sleep(0.5)
    thinkphp_view_recent_xff_sqli_verify(url)
  except Exception as e:
    print("异常对象内容%s"%e)