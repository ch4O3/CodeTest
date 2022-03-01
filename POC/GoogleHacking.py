# -*- coding: utf-8 -*-
from glob import escape
from requests.models import Response
from openpyxl import Workbook
from lxml import etree
import requests
import random
import time
import os
import re

requests.packages.urllib3.disable_warnings()

#需要爬取的最大页数
page_count = 10

#百度搜索引擎cookie
cookie_for_baidu = 'BAIDUID=265D59D7695DD0461CF22C5BCD992D51:FG=1; BIDUPSID=819168A2E6D1CA2818B424154F15ADF4; PSTM=1629473616; __yjs_duid=1_b00af70aaa0d12ecf29fc6743208909b1630429473988; BD_UPN=12314753; BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; kleck=f608ce683d55f785468f99b9989197c8; BAIDUID_BFESS=265D59D7695DD0461CF22C5BCD992D51:FG=1; COOKIE_SESSION=1522726_0_5_7_3_9_1_1_4_4_0_2_13424_0_0_0_1632986451_0_1645732850%7C9%230_0_1645732850%7C1; Hm_lvt_aec699bb6442ba076c8981c6dc490771=1645732819; BD_HOME=1; H_PS_PSSID=35837_34429_35105_35979_35866_34584_35872_35246_35949_35802_35315_26350_22160; BA_HECTOR=a5al8l250k344h24l71h1hgv00r; delPer=0; BD_CK_SAM=1; PSINO=3; H_PS_645EC=35c9cNYrvICHcaUJDBy1V%2BcIKvrR473QXTacvIyqsaUWiVTo2oFo0qez%2FOQ; baikeVisitId=06767cfd-e823-4ea8-b97f-59db5f8b5e1e; BDSVRTM=505'
#360搜索引擎cookie
cookie_for_360= 'QiHooGUID=DB25718746568B49F0CB53F6987B6971.1633741882041; __guid=15484592.4088915709789373000.1633741881671.7664; count=11; so-like-red=2; dpr=1.25; webp=1; so_huid=11MbTDeaDjgcmBpgnlPgSTXru5ykEFagXAyaqtDpJao3c%3D; __huid=11MbTDeaDjgcmBpgnlPgSTXru5ykEFagXAyaqtDpJao3c%3D; _uc_silent=1; WSADFK=666c590a211e3a7bd7ed4afac164254e.1645754826.1548; ba93630cd3b65ed2e1753408498ffefa=1645754826; erules=p1-37%7Cp3-8%7Cp4-91%7Cp2-16%7Cecl-13%7Ckd-15; gtHuid=1'
#Bing搜索引擎cookie
cookie_for_Bing = 'SUID=M; MUID=29EBBBE5A54167F20568AAB3A4276683; MUIDB=29EBBBE5A54167F20568AAB3A4276683; _EDGE_S=F=1&SID=2CBA98ED004364B30BCF89BB01256583; _EDGE_V=1; SRCHD=AF=NOFORM; SRCHUID=V=2&GUID=2CE1154E38F4441A8CA3A05EA5139D43&dmnchg=1; SRCHUSR=DOB=20220225&T=1645771520000&TPC=1645771523000; SRCHHPGUSR=SRCHLANG=zh-Hans&BZA=0&BRW=XW&BRH=M&CW=1536&CH=703&SW=1536&SH=864&DPR=1.25&UTC=480&DM=0&HV=1645771586&WTS=63781368320; _SS=SID=2CBA98ED004364B30BCF89BB01256583; ZHCHATSTRONGATTRACT=TRUE; ipv6=hit=1645775124797&t=4; ZHCHATWEAKATTRACT=TRUE; SNRHOP=I=&TS='
#Sogou搜索引擎cookie
cookie_for_Sogou = 'SNUID=27FE60452A2FF2FAC017E2522BCD61A7; IPLOC=CN3601; SUID=85D54B6F374A910A0000000061C14D39; SUV=1640058170355816; ABTEST=0|1645770989|v17; ld=Kkllllllll2Ap40HlllllpwYmSklllllb1sqRyllllGlllllpylll5@@@@@@@@@@; browerV=3; osV=1; LSTMV=744%2C36; LCLKINT=86092'
#Google搜索引擎cookie
cookie_for_Google = '1P_JAR=2022-02-28-07; NID=511=WfvSZnKueRIVdmd1Jn7RZyZdKvK_yuctvkWtNDt42nghVQIQZtVpW5WKkUqXodTpVDo49pUMF3w3SMOy1hdaHQN1eCoLqyl3y0MSu-2bmLXO2RXwlGJFs7b7OPukdUktQggR-dOotJFY5SB05V8E0kNqi-LIjzPhXDGgZo4Fw_8; OGPC=19019112-1:; OGP=-19019112:'

wb = Workbook()#当前结果文件
ws = wb.active#excel表格
ws.append(['来源','标题','链接','快照'])
class WebRequest(object):
    name = "Web_Request"

    def __init__(self, *args, **kwargs):
        self.response = Response()

    @property
    def user_agent(self):
        """
        return an User-Agent at random
        :return:
        """
        ua_list = [
            #'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
            #'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
            #'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
            #'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
            #'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
            #'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
            #'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
            #'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
            'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36',
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

    def get(self, url, header=None, retry_time=2, retry_interval=2, timeout=5, *args, **kwargs):
        """
        get method
        :param url: target url
        :param header: headers
        :param retry_time: retry time
        :param retry_interval: retry interval
        :param timeout: network timeout
        :return:
        """
        headers = self.header
        if header and isinstance(header, dict):
            headers.update(header)
        while True:
            try:
                self.response = requests.get(url, headers=headers, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as e:
                print("requests: %s error: %s" % (url, str(e)))
                retry_time -= 1
                if retry_time <= 0:
                    resp = Response()
                    resp.status_code = 200
                    return self
                print("retry %s second after" % retry_interval)
                time.sleep(retry_interval)
                
    def respheader(self, key):
        try:
            return self.response.headers[key]
        except Exception as e:
            #print(str(e))
            return ''
        
    @property
    def code(self):
        encodings = requests.utils.get_encodings_from_content(self.response.text)
        if encodings:
            return encodings[0]
        else:
            return self.response.apparent_encoding

    @property
    def tree(self):
        return etree.HTML(self.response.content.decode(self.code, 'ignore'))

    @property
    def text(self):
        return self.response.text
    
    @property
    def status_code(self):
        return self.response.status_code

    @property
    def json(self):
        try:
            return self.response.json()
        except Exception as e:
            print(str(e))
            return {}

class UrlFetcher(object):
    """
    Url getter
    """

    @staticmethod
    def HackingUrl_fromBaidu(Rulestr, page_count, timestr):
        """
        百度 https://www.baidu.com
        :return:
        """
        header_baidu = {
            "Cookie":cookie_for_baidu
            }
        #所有匹配的div
        divs = []
        #页数目录列表
        index = ['1']
        #地址
        url = 'https://www.baidu.com/s?wd={}&pn={}0'
        
        while True:
            try:
                req = WebRequest().get(url.format(Rulestr, str(int(index[-1])-1)), header=header_baidu, allow_redirects=False)
                html = req.text
                #语法错误
                if '抱歉' in html:
                    print('[-]百度未找到结果, 请输入正确语法!')
                    return
                elif req.status_code == 302:
                    print('[-]百度安全验证, 请更换cookie!')
                    return
                html_tree = req.tree
                divs = html_tree.xpath("(//div[contains(@class,'result c-container')])")
                #停止0.5秒
                time.sleep(0.5)
                #当前页面关联的页数
                tr = html_tree.xpath("//span[@class='page-item_M4MDr pc']/text()")
                if len(tr) == 0:
                    tr = ['1']
                #当前页面关联的最后页数和当前请求的页数一致时,说明本次访问的页面为最后一页
                if tr[-1] == index[-1]:
                    break
                #去重
                index = list(set(index+tr))
                #排序
                index.sort(key = lambda i:int(i))
                #判断已经爬取的最大页数和需要爬取的页数
                if page_count < int(index[-1]):
                    break
            except Exception as e:
                print('[-]查找 百度 过程中发生异常, %s'%type(e))
                return
            
        #限制查找页数
        if int(index[-1]) > page_count:
            print('[*]当前可爬取百度 %s 页, 开始限制爬取页数为 %s 页...'%(len(index),page_count))
            index = index[:index.index(str(page_count))+1]
        
        print('[+]共爬取百度 %s 页'%len(index))
        for i in index:
            try:
                #每次请求一页
                html_tree = WebRequest().get(url.format(Rulestr, str(int(i)-1)), header=header_baidu, allow_redirects=False).tree
                divs = html_tree.xpath("(//div[contains(@class,'result c-container')])")
                #请求一次, 暂缓0.5秒
                time.sleep(0.5)
                for div in divs:
                    try:
                        title = div.xpath("./h3[@class='t']//a/text()")[0]
                    except Exception:
                        title = 'null'
                    try:
                        baidulink = div.xpath("./h3[@class='t']//a/@href")[0]
                        link = WebRequest().get(baidulink, header=header_baidu, allow_redirects=False).respheader('Location')
                    except Exception:
                        link = 'null'
                    try:
                        cache = div.xpath(".//a[@class='m c-gap-left c-color-gray kuaizhao snapshoot']/@href")[0]
                    except Exception:
                        cache = 'null'
                    ws.append(['Baidu',title, link, cache])
                #print('[+]爬取百度第 %s 页成功!'%i)
            except Exception as e:
                print('[-]爬取百度第 %s 页出错, 跳过本次爬取...'%i)
                continue
        wb.save('./result/%s_%s.xlsx'%('GoogleHacking',timestr))
        print('[+]爬取百度完成!')
        
    @staticmethod
    def HackingUrl_from360(Rulestr, page_count, timestr):
        """
        360 https://www.so.com
        :return:
        """
        header_360 = {
            "Cookie":cookie_for_360
            }
        #所有匹配的div
        divs = []
        #页数目录列表
        index = ['1']
        #地址
        url = 'https://www.so.com/s?q={}&pn={}'
        
        while True:
            try:
                req = WebRequest().get(url.format(Rulestr, index[-1]), header=header_360, allow_redirects=False)
                html = req.text
                #语法错误
                if '抱歉' in html:
                    print('[-]360未找到结果, 请输入正确语法!')
                    return
                #360安全验证
                elif 'qcaptcha' in req.respheader('Location') and req.status_code == 302:
                    print('[-]360安全验证, 请更换cookie!')
                    return
                html_tree = req.tree
                divs = html_tree.xpath("(//li[@class='res-list'])")
                #停止1.0秒
                time.sleep(1.0)
                #当前页面关联的页数
                tr = html_tree.xpath("//div[@id='page']//a/text()")
                if '上一页' in tr:
                    tr.remove('上一页')
                if '下一页' in tr:
                    tr.remove('下一页')
                if len(tr) == 0:
                    tr = ['1']
                #当前页面关联的最后页数和当前请求的页数一致时,说明本次访问的页面为最后一页
                if tr[-1] == index[-1]:
                    break
                #去重
                index = list(set(index+tr))
                #排序
                index.sort(key = lambda i:int(i))
                #判断已经爬取的最大页数和需要爬取的页数
                if page_count < int(index[-1]):
                    break
            #发生异常, 说明当前只有一页
            except Exception as e:
                print('[-]查找 360 过程中发生异常, %s'%type(e))
                return
            
        #限制查找页数
        if int(index[-1]) > page_count:
            print('[*]当前可爬取360 %s 页, 开始限制爬取页数为 %s 页...'%(len(index),page_count))
            index = index[:index.index(str(page_count))+1]
        
        print('[+]共爬取360 %s 页'%len(index))
        for i in index:
            try:
                #每次请求一页
                html_tree = WebRequest().get(url.format(Rulestr, i), header=header_360, allow_redirects=False).tree
                divs = html_tree.xpath("(//li[@class='res-list'])")
                #请求一次, 暂缓2.0秒, 360云防护
                time.sleep(2.0)
                for div in divs:
                    try:
                        title = div.xpath("./h3[@class='res-title ']/a/text()")[0]
                    except Exception:
                        title = 'null'
                    try:
                        link = div.xpath("./h3[@class='res-title ']/a/@data-mdurl")[0]
                        #for360link = div.xpath(".//a[@class='g-linkinfo-a']/@href")[0]
                        #link = re.search('URL=\'(.*)\'', WebRequest().get(for360link, allow_redirects=False).text).group(1)
                    except Exception:
                        link = 'null'
                    try:
                        cache = div.xpath(".//a[@class='m']/@href")[0]
                    except Exception:
                        cache = 'null'
                    ws.append(['360',title, link, cache])
                #print('[+]爬取360第 %s 页成功!'%i)
            except Exception as e:
                print('[-]爬取360第 %s 页出错, 跳过本次爬取...'%i)
                continue
        wb.save('./result/%s_%s.xlsx'%('GoogleHacking',timestr))
        print('[+]爬取360完成!')
        

    @staticmethod
    def HackingUrl_fromBing(Rulestr, page_count, timestr):
        """
        Bing https://cn.bing.com
        :return:
        """
        header_Bing = {
            "Cookie":cookie_for_Bing
            }
        #所有匹配的div
        divs = []
        #页数目录列表
        index = ['1']
        #地址
        url = 'https://cn.bing.com/search?q={}&first={}1'
        
        while True:
            try:
                req = WebRequest().get(url.format(Rulestr, str(int(index[-1])-1)), header=header_Bing)
                html = req.text
                #语法错误
                if '没有与此相关的结果' in html:
                    print('[-]Bing未找到结果, 请输入正确语法!')
                    return
                html_tree = req.tree
                divs = html_tree.xpath("(//li[@class='b_algo'])")
                #停止1.0秒
                time.sleep(1.0)
                #当前页面关联的页数
                tr = html_tree.xpath("(//li[@class='b_pag']//li)/a/text()")
                if len(tr) == 0:
                    tr = ['1']
                #当前页面关联的最后页数和当前请求的页数一致时,说明本次访问的页面为最后一页
                if tr[-1] == index[-1]:
                    break
                #去重
                index = list(set(index+tr))
                #排序
                index.sort(key = lambda i:int(i))
                #判断已经爬取的最大页数和需要爬取的页数
                if page_count < int(index[-1]):
                    break
            #发生异常, 说明当前只有一页
            except Exception as e:
                print('[-]查找 Bing 过程中发生异常, %s'%type(e))
                return
        
        #限制查找页数
        if int(index[-1]) > page_count:
            print('[*]当前可爬取Bing %s 页, 开始限制爬取页数为 %s 页...'%(len(index),page_count))
            index = index[:index.index(str(page_count))+1]
        
        print('[+]共爬取Bing %s 页'%len(index))
        for i in index:
            try:
                #每次请求一页
                html_tree = WebRequest().get(url.format(Rulestr, str(int(i)-1)), header=header_Bing).tree
                divs = html_tree.xpath("(//li[@class='b_algo'])")
                #请求一次, 暂缓0.5秒
                time.sleep(0.5)
                for div in divs:
                    try:
                        title = div.xpath(".//h2/a/text()")[0]
                    except Exception:
                        title = 'null'
                    try:
                        link = div.xpath(".//h2/a/@href")[0]
                    except Exception:
                        link = 'null'
                    try:
                        cache = 'null'
                    except Exception:
                        cache = 'null'
                    ws.append(['Bing',title, link, cache])
                #print('[+]爬取Bing第 %s 页成功!'%i)
            except Exception as e:
                print('[-]爬取Bing第 %s 页出错, 跳过本次爬取...'%i)
                continue
        wb.save('./result/%s_%s.xlsx'%('GoogleHacking',timestr))
        print('[+]爬取Bing完成!')
        
    @staticmethod
    def HackingUrl_fromSogou(Rulestr, page_count, timestr):
        """
        sogou https://www.sogou.com
        :return:
        """
        header_Sogou = {
            "Cookie":cookie_for_Sogou
            }
        #所有匹配的div
        divs = []
        #页数目录列表
        index = ['1']
        #地址
        url = 'https://www.sogou.com/web?query={}&page={}'
        
        while True:
            try:
                req = WebRequest().get(url.format(Rulestr, index[-1]), header=header_Sogou, allow_redirects=False)
                html = req.text
                html_tree = req.tree
                divs = html_tree.xpath("//div[@class='vrwrap']")
                #停止1.0秒
                time.sleep(1.0)
                #当前页面关联的页数
                tr = html_tree.xpath("//div[@id='pagebar_container']/a/text()")
                if '上一页' in tr:
                    tr.remove('上一页')
                if '下一页' in tr:
                    tr.remove('下一页')
                if len(tr) == 0:
                    tr = ['1']
                #当前页面关联的最后页数和当前请求的页数一致时,说明本次访问的页面为最后一页
                if tr[-1] == index[-1]:
                    break
                #去重
                index = list(set(index+tr))
                #排序
                index.sort(key = lambda i:int(i))
                #判断已经爬取的最大页数和需要爬取的页数
                if page_count < int(index[-1]):
                    break
            #发生异常, 说明当前只有一页
            except Exception as e:
                print('[-]查找Sogou过程中发生异常, %s'%type(e))
                return
        
        #限制查找页数
        if int(index[-1]) > page_count:
            print('[*]当前可爬取Sogou %s 页, 开始限制爬取页数为 %s 页...'%(len(index),page_count))
            index = index[:index.index(str(page_count))+1]
        
        print('[+]共爬取Sogou %s 页'%len(index))
        for i in index:
            try:
                #每次请求一页
                html_tree = WebRequest().get(url.format(Rulestr, i), header=header_Sogou, allow_redirects=False).tree
                divs = html_tree.xpath("//div[@class='vrwrap']")
                #请求一次, 暂缓0.5秒
                time.sleep(0.5)
                for div in divs[1:]:
                    try:
                        title = div.xpath(".//h3/a/text()")[0]
                    except Exception:
                        title = 'null'
                    try:
                        forSogoulink = 'https://www.sogou.com' + div.xpath(".//h3/a/@href")[0]
                        link = re.search('URL=\'(.*)\'', WebRequest().get(forSogoulink, allow_redirects=False).text).group(1)
                    except Exception:
                        link = 'null'
                    try:
                        cache = 'null'
                    except Exception:
                        cache = 'null'
                    ws.append(['Sogou',title, link, cache])
                #print('[+]爬取Sogou第 %s 页成功!'%i)
            except Exception as e:
                print('[-]爬取Sogou第 %s 页出错, 跳过本次爬取...'%i)
                continue
        wb.save('./result/%s_%s.xlsx'%('GoogleHacking',timestr))
        print('[+]爬取Sogou完成!')



    @staticmethod
    def HackingUrl_fromGoogle(Rulestr, page_count, timestr):
        """
        Google https://www.google.com
        :return:
        """
        header_Google = {
            "Cookie":cookie_for_Google
            }
        #所有匹配的div
        divs = []
        #页数目录列表
        index = ['1']
        #地址
        url = 'https://www.google.com/search?q={}&start={}0'
        
        while True:
            try:
                req = WebRequest().get(url.format(Rulestr, str(int(index[-1])-1)), header=header_Google, allow_redirects=False)
                html = req.text
                #语法错误
                if '找不到' in html:
                    print('[-]Google未找到结果, 请输入正确语法!')
                    return
                html_tree = req.tree
                divs = html_tree.xpath("(//div[@class='yuRUbf'])")
                #停止1.0秒
                time.sleep(1.0)
                #当前页面关联的页数
                tr = html_tree.xpath("//table[@class='AaVjTc']//a[@class='fl']/text()")
                tr_now = html_tree.xpath("//table[@class='AaVjTc']//td[@class='YyVfkd']/text()")
                #合并
                tr = tr + tr_now
                if '上一页' in tr:
                    tr.remove('上一页')
                if '下一页' in tr:
                    tr.remove('下一页')
                if len(tr) == 0:
                    tr = ['1']
                #增加一次排序
                tr.sort(key = lambda i:int(i))
                #当前页面关联的最后页数和当前请求的页数一致时,说明本次访问的页面为最后一页
                if tr[-1] == index[-1]:
                    break
                #去重
                index = list(set(index+tr))
                #排序
                index.sort(key = lambda i:int(i))
                #判断已经爬取的最大页数和需要爬取的页数
                if page_count < int(index[-1]):
                    break
            except Exception as e:
                print('[-]查找 Google 过程中发生异常, %s'%type(e))
                return

        #限制查找页数
        if int(index[-1]) > page_count:
            print('[*]当前可爬取Google %s 页, 开始限制爬取页数为 %s 页...'%(len(index),page_count))
            index = index[:index.index(str(page_count))+1]
        
        print('[+]共爬取Google %s 页'%len(index))
        for i in index:
            try:
                #每次请求一页
                html_tree = WebRequest().get(url.format(Rulestr, str(int(i)-1)), header=header_Google, allow_redirects=False).tree
                divs = html_tree.xpath("(//div[@class='yuRUbf'])")
                #请求一次, 暂缓0.5秒
                time.sleep(0.5)
                for div in divs:
                    try:
                        title = div.xpath(".//h3/text()")[0]
                    except Exception:
                        title = 'null'
                    try:
                        link = div.xpath('./a/@href')[0]
                    except Exception:
                        link = 'null'
                    try:
                        cache = div.xpath('.//a[@class=\'fl\']/@href')[0]
                    except Exception:
                        cache = 'null'
                    ws.append(['Google',title, link, cache])
                #print('[+]爬取Sogou第 %s 页成功!'%i)
            except Exception as e:
                print('[-]爬取Google第 %s 页出错, 跳过本次爬取...'%i)
                continue
        wb.save('./result/%s_%s.xlsx'%('GoogleHacking',timestr))
        print('[+]爬取Google完成!')

def checkProxy():
    # 查看是否能连通google
    try:
        requests.get("https://www.google.com",timeout=5,verify=False)
    except Exception:
        return 0
    return 1


def check(**kwargs):
    timestr = time.strftime("%Y%m%d_%H%M%S")#获取当前时间
    p = UrlFetcher()
    p.HackingUrl_fromBaidu(kwargs['url'], page_count, timestr)
    time.sleep(0.5)
    p.HackingUrl_from360(kwargs['url'], page_count, timestr)
    time.sleep(0.5)
    p.HackingUrl_fromBing(kwargs['url'], page_count, timestr)
    time.sleep(0.5)
    #p.HackingUrl_fromSogou(kwargs['url'], page_count, timestr)
    time.sleep(0.5)
    if checkProxy():
        p.HackingUrl_fromGoogle(kwargs['url'], page_count, timestr)
    else:
        print('[-]连接Google失败, 无法通过Google爬取数据')
    
    print('[*]爬取完成, 请查看结果文件 %s_%s.xlsx'%('GoogleHacking',timestr))

if __name__ == '__main__':
    os.environ['HTTP_PROXY'] = '127.0.0.1:8080'
    os.environ['HTTPS_PROXY'] = '127.0.0.1:8080'
    p = UrlFetcher()
    #google = input("[*]请输入Google语法->")
    #page_count = int(input("[*]请输入需要爬取的页数->"))
    timestr = time.strftime("%Y%m%d_%H%M%S")#获取当前时间
    
    google = 'site:jxedu.gov.cn'
    #p.HackingUrl_fromBaidu(google, page_count, timestr)
    #p.HackingUrl_from360(google, page_count, timestr)
    #p.HackingUrl_fromBing(google, page_count, timestr)
    #if checkProxy():
    #    p.HackingUrl_fromGoogle(google, page_count, timestr)
    #else:
    #    print('[-]连接Google失败, 无法通过Google爬取数据')
    p.HackingUrl_fromGoogle(google, page_count, timestr)
    #p.HackingUrl_fromGoogle(google, page_count, timestr)
    print('[*]爬取完成, 请查看结果文件 %s_%s.xlsx'%('GoogleHacking',timestr))







