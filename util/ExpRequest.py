# -*- coding: utf-8 -*-
from requests.models import Response
from lxml import etree
from ClassCongregation import color
from settings import Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval
import re
import requests
import datetime
import random
import time

from Proxy.handler.logHandler import LogHandler

requests.packages.urllib3.disable_warnings()


class ExpRequest(object):
    
    def __init__(self, pocname, output=None, *args, **kwargs):
        self.log = LogHandler(pocname, file=False)
        self.response = Response()
        self.output = output
        self.timeout = int(Ent_B_Top_timeout.get())
        self.retry_time = int(Ent_B_Top_retry_time.get())
        self.retry_interval = int(Ent_B_Top_retry_interval.get())

    @property
    def user_agent(self):
        """
        return an User-Agent at random
        :return:
        """
        ua_list = [
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
            'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        ]
        return random.choice(ua_list)

    @property
    def header(self):
        """
        basic header
        :return:
        """
        return {'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Connection': 'keep-alive',
                'Accept-Language': 'zh-CN,zh;q=0.8'}

    def get(self, url, headers=None, retry_time=3, retry_interval=3, timeout=3, *args, **kwargs):
        """
        get method
        :param url: target url
        :param header: headers
        :param retry_time: retry time
        :param retry_interval: retry interval
        :param timeout: network timeout
        :return:
        """
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        timeout = self.timeout
        header = self.header
        if headers and isinstance(headers, dict):
            header.update(headers)
        while True:
            try:
                self.response = requests.get(url, headers=header, timeout=timeout, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                #self.log.error("requests: %s error: %s" % (url, str(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                    #resp = Response()
                    #resp.status_code = 500
                    #return self
                self.log.info("retry %s second after" % retry_interval)
                time.sleep(retry_interval)   

    
    def post(self, url, headers=None, retry_time=3, retry_interval=3, timeout=3, *args, **kwargs):
        """
        post method
        :param url: target url
        :param headers: headers
        :param retry_time: retry time
        :param retry_interval: retry interval
        :param timeout: network timeout
        :return:
        """
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        timeout = self.timeout
        header = self.header
        if headers and isinstance(headers, dict):
            header.update(headers)
        while True:
            try:
                self.response = requests.post(url, headers=header, timeout=timeout, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                #self.log.error("requests: %s error: %s" % (url, str(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                    #resp = Response()
                    #resp.status_code = 500
                    #return self
                self.log.info("retry %s second after" % retry_interval)
                time.sleep(retry_interval)

    def put(self, url, headers=None, retry_time=3, retry_interval=3, timeout=3, *args, **kwargs):
        """
        put method
        :param url: target url
        :param headers: headers
        :param retry_time: retry time
        :param retry_interval: retry interval
        :param timeout: network timeout
        :return:
        """
        retry_time = self.retry_time
        retry_interval = self.retry_interval
        timeout = self.timeout
        header = self.header
        if headers and isinstance(headers, dict):
            header.update(headers)
        while True:
            try:
                self.response = requests.put(url, headers=header, timeout=timeout, *args, **kwargs)
                return self
            except Exception as error:
                if isinstance(error, requests.exceptions.Timeout):
                    self.output.timeout_output()
                elif isinstance(error, requests.exceptions.ConnectionError):
                    self.output.connection_output()
                else:
                    self.output.error_output(str(type(error)))
                #self.log.error("requests: %s error: %s" % (url, str(error)))
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} , 请检查网络环境!'.format(str(type(error))))
                    #resp = Response()
                    #resp.status_code = 500
                    #return self
                self.log.info("retry %s second after" % retry_interval)
                time.sleep(retry_interval)     

    @property
    def code(self):
        encodings = requests.utils.get_encodings_from_content(self.response.text)
        if encodings:
            return encodings[0]
        else:
            return self.response.apparent_encoding

    @property
    def status_code(self):
        return self.response.status_code

    @property
    def headers(self):
        return self.response.headers
    
    @property
    def title(self):
        return "".join(re.findall('<title>(.+)</title>',self.response.text))

    @property
    def tree(self):
        return etree.HTML(self.response.content.decode(self.code, 'ignore'))

    @property
    def text(self):
        return self.response.text

    @property
    def json(self):
        try:
            return self.response.json()
        except Exception as e:
            self.log.error(str(e))
            return {}

#结果输出
class Output(object):
    def __init__(self, pocname=''):
        self.error_msg = tuple()
        self.result = {}
        self.params = {}
        self.status = {}
        self.pocname = pocname

    def result_error(self, error):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ error, 'cyan')

    def timeout_output(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" check failed because timeout !!!", 'cyan')

    def connection_output(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" check failed because unable to connect !!!", 'cyan')

    def error_output(self, error):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" "+ error +" !!!", 'cyan')

    def no_echo_success(self, method, info):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[+] The target is "+ self.pocname +" ["+ method +"] "+ info, 'green')

    def echo_success(self, method, info):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[+] The target is "+ self.pocname +" ["+ method +"] "+ info +" echo_success", 'green')

    def fail(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[-] The target no "+ self.pocname +"                    ", 'magenta')

    def to_dict(self):
        return self.__dict__

#时间类
class Timed(object):
    @staticmethod
    def timed(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    @staticmethod
    def timed_line(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    @staticmethod
    def no_color_timed(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        print("["+str(now)[11:19]+"] ",end="")