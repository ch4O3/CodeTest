#############################################################
###                                                  
###   ▄▄▄▄                ▄▄▄     ▄▄▄▄    ▀      ▄   
###  ▀   ▀█ ▄   ▄  ▄▄▄▄     █    ▄▀  ▀▄ ▄▄▄    ▄▄█▄▄ 
###    ▄▄▄▀  █▄█   █▀ ▀█    █    █  ▄ █   █      █   
###      ▀█  ▄█▄   █   █    █    █    █   █      █   
###  ▀▄▄▄█▀ ▄▀ ▀▄  ██▄█▀  ▄▄█▄▄   █▄▄█  ▄▄█▄▄    ▀▄▄ 
###                █                                 
###                ▀                                 
###                                                          
### name: xcdn.py
### function: try to get the actual ip behind cdn
### date: 2016-11-05
### author: quanyechavshuo
### blog: http://3xp10it.cc
#############################################################
# usage:python3 xcdn.py www.baidu.com
# -*- coding: utf-8 -*-
#import time
#import os
#os.system("pip3 install exp10it -U --no-cache-dir")    
#from exp10it import figlet2file
#figlet2file("3xp10it",0,True)
#time.sleep(1)

from exp10it import get_root_domain
from exp10it import get_string_from_command
from exp10it import get_http_or_https
from exp10it import post_request
from exp10it import get_request
from exp10it import checkvpn
import sys
import re
import subprocess,requests
from bs4 import BeautifulSoup

class Xcdn(object):

    def __init__(self,domain):
        if domain[:4]=="http":
            print("不能包含http和https字样，如果有端口要加上端口")
            return
        headers = {
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
            #这里一定要设置UA，否则会出现错误
        }
        
        if ':'in domain:
            searchobj = re.search('(.*):(.*)$', domain)
            self.port = searchobj.group(2)
            self.domain = searchobj.group(1)
            #self.http_or_https=get_http_or_https(self.domain)
            if self.port == '80':
                self.http_or_https = 'http'
            elif self.port == '443':
                self.http_or_https = 'https'
            else:
                self.http_or_https = get_http_or_https(self.domain)
        else:
            self.domain=domain
            self.http_or_https = get_http_or_https(self.domain)

            if self.http_or_https == 'http':
                self.port = '80'
            else:
                self.port = '443'
            
        #print('domain使用的协议是:%s' % self.http_or_https)
        rep_test = requests.get(self.http_or_https+"://"+self.domain+":"+self.port,timeout=10, verify=False, headers=headers).text

        soup = BeautifulSoup(rep_test, 'lxml')
        self.domain_title= soup.title.string
        print('domain使用的协议是:%s, %s' %(self.http_or_https,self.domain_title))
        #print('domain使用的协议是:%s' % self.http_or_https)
        #result=get_request(self.http_or_https+"://"+self.domain,'seleniumPhantomJS')
        #self.domain_title=result['title']
        #下面调用相当于main函数的get_actual_ip_from_domain函数
        #self.get_ip_value_from_ip138()
        #self.get_ip_value_from_fofa()
        #'''
        actual_ip = self.get_actual_ip_from_domain()
        if actual_ip != 0:
            print("恭喜, %s 的真实ip是 %s" % (self.domain, actual_ip))
        #下面用来存放关键返回值
        self.return_value=actual_ip
#'''
        
    def domain_has_cdn(self):
        # 检测domain是否有cdn
        # 有cdn时,返回一个字典,如果cdn是cloudflare，返回{'has_cdn':1,'is_cloud_flare':1}
        # 否则返回{'has_cdn':1,'is_cloud_flare':0}或{'has_cdn':0,'is_cloud_flare':0}
        import re
        print("[*]现在检测domain:%s是否有cdn" % self.domain)
        has_cdn = 0
        # ns记录和mx记录一样,都要查顶级域名,eg.dig +short www.baidu.com ns VS dig +short baidu.com ns
        popen = subprocess.Popen("nslookup -type=ns %s" % get_root_domain(self.domain), stdout=subprocess.PIPE ,shell=True,close_fds=True)
        #result = get_string_from_command("nslookup -type=ns %s" % get_root_domain(self.domain))
        result,drr = popen.communicate()
        result = result.decode("utf-8","ignore")
        pattern = re.compile(
            "(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)""(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)"r"(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)", re.I)
        cloudflare_pattern = re.compile("cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare""cloudflare"r"cloudflare", re.I)
        if re.search(pattern, result):
            if re.search(cloudflare_pattern, result):
                print("has_cdn=1 from ns,and cdn is cloudflare")
                return {'has_cdn': 1, 'is_cloud_flare': 1}
            else:
                print("has_cdn=1 from ns")
                return {'has_cdn': 1, 'is_cloud_flare': 0}
        else:
            # 下面通过a记录个数来判断,如果a记录个数>1个,认为有cdn
            result = get_string_from_command("nslookup -type=a %s" % self.domain)
            find_a_record_pattern = re.findall("((\\d{1,3}\\.){3}\\d{1,3})", result)
            #print(find_a_record_pattern)
            if find_a_record_pattern:
                ip_count = 0
                for each in find_a_record_pattern:
                    ip_count += 1
                if ip_count > 1:
                    has_cdn = 1
                    return {'has_cdn': 1, 'is_cloud_flare': 0}
        return {'has_cdn': 0, 'is_cloud_flare': 0}


    def get_domain_actual_ip_from_phpinfo(self):
        # 从phpinfo页面尝试获得真实ip
        print("1)尝试从domain:%s可能存在的phpinfo页面获取真实ip" % self.domain)
        phpinfo_page_list = ["info.php", "phpinfo.php", "test.php", "l.php"]
        for each in phpinfo_page_list:
            url = self.http_or_https + "://" + self.domain + ":" + self.port +"/" + each
            print("[*]现在访问%s" % url)
            visit = get_request(url,'seleniumPhantomJS')
            code = visit['code']
            content = visit['content']
            pattern = re.compile("remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr""remote_addr"r"remote_addr", re.I)
            if code == 200 and re.search(pattern, content):
                print(each)
                actual_ip = re.search("REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+""REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+"r"REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+", content).group(1)
                return actual_ip
        # return 0代表没有通过phpinfo页面得到真实ip
        return 0

#ok
    def check_if_ip_is_actual_ip_of_domain(self,ip):
        headers = { 
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
            #这里一定要设置UA，否则会出现错误
        }

        #result = get_request(self.http_or_https+"://"+ip,'seleniumPhantomJS')
        #hosts_changed_domain_title = result['title']

        rep_test = requests.get(self.http_or_https + "://%s" % ip + ":"+self.port,timeout=5, verify=False, headers=headers).text

        soup = BeautifulSoup(rep_test, 'lxml')
        #text_title = soup.title.string.decode("utf-8").encode("utf-8")
        hosts_changed_domain_title= soup.title.string
        #这里要用title判断,html判断不可以,title相同则认为相同
        if self.domain_title == hosts_changed_domain_title:
            print("[+]检测到真实ip!!!!!!")
            return True
        else:
            print("[-] {} 不是域名的真实ip, {}".format(ip,hosts_changed_domain_title))
            return False

#ok
    def get_c_80_or_443_list(self,ip):
        # 得到ip的整个c段的开放80端口或443端口的ip列表
        if "not found" in get_string_from_command("nmap"):
            #这里不用nmap扫描,nmap扫描结果不准
            #os.system("apt-get install masscan")
            print("[-]需要安装nmap命令")
            return 0
        scanPort = self.port
        print("[*]现在进行 %s 的c段开了 %s 端口机器的扫描" %(ip,scanPort))
        '''
        if self.http_or_https=="http":
            scanPort=80
            print("[*]现在进行%s的c段开了80端口机器的扫描" % ip)
        if self.http_or_https=="https":
            scanPort=443
            print("[*]现在进行%s的c段开了443端口机器的扫描" % ip)
        '''
        popen = subprocess.Popen("nmap -p %s -sS -sV -T4 -v -n --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -Pn --open %s/24" % (scanPort,ip), stdout=subprocess.PIPE ,shell=True,close_fds=True)
        #masscan_command = "nmap -p %d -sS -sV -T4 -v -F -n --min-hostgroup 4 --min-parallelism 1024 --host-timeout 30 -Pn --open %s/24 > ./masscan.txt" % (scanPort,ip)
        result,drr = popen.communicate()
        result = result.decode("utf-8","ignore")
        allIP=re.findall("((\\d{1,3}\\.){3}\\d{1,3})",result)
        ipList=[]
        for each in allIP:
            ipList.append(each[0])
        #print(ipList)
        ipList = list(set(ipList))#去重处理
        return ipList

#ok
    def check_if_ip_c_machines_has_actual_ip_of_domain(self,ip):
        # 检测ip的c段有没有domain的真实ip,如果有则返回真实ip,如果没有则返回0
        print("[*]现在检测ip为%s的c段中有没有%s的真实ip" % (ip,self.domain))
        target_list=self.get_c_80_or_443_list(ip)
        #print(target_list)
        for each_ip in target_list:
            try:
                if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                    print(each_ip)
                    return each_ip
            except Exception as e:
                print("[-]访问 %s 失败,跳过该IP测试"%each_ip)
                continue
        return 0

#ok
    def get_ip_from_mx_record(self):
        # 从mx记录中得到ip列表,尝试从mx记录中的c段中找真实ip
        print("[*]尝试从mx记录中找和%s顶级域名相同的mx主机" % self.domain)
        import socket
        # domain.eg:www.baidu.com
        from exp10it import get_root_domain
        root_domain = get_root_domain(self.domain)
        from exp10it import get_string_from_command
        popen = subprocess.Popen("nslookup -type=mx %s" % root_domain, stdout=subprocess.PIPE ,shell=True,close_fds=True)
        result,drr = popen.communicate()
        result = result.decode('utf-8','ignore')
        print(result)
        #result = get_string_from_command("nslookup -type=mx %s" % root_domain)
        sub_domains_list = re.findall("(mail exchanger = )(.*\\.%s)" % root_domain.replace(".", "\\."), result)
        ip_list = []
        #print(sub_domains_list)
        for each in sub_domains_list:
            #print(each)
            ip = socket.gethostbyname_ex(each[1])[2]
            #print(ip)
            if ip[0] not in ip_list:
                ip_list.append(ip[0])
        return ip_list

#ok
    def check_if_mx_c_machines_has_actual_ip_of_domain(self):
        # 检测domain的mx记录所在ip[或ip列表]的c段中有没有domain的真实ip
        # 有则返回真实ip,没有则返回0
        print("2)尝试从mx记录的c段中查找是否存在%s的真实ip" % self.domain)
        ip_list = self.get_ip_from_mx_record()
        ip_list = list(set(ip_list))#去重处理
        print(ip_list)
        if ip_list != []:
            for each_ip in ip_list:
                result = self.check_if_ip_c_machines_has_actual_ip_of_domain(each_ip)
                if result != 0:
                    return result
                else:
                    continue
        return 0

#no
    def get_ip_value_from_online_cloudflare_interface(self):
        # 从在线的cloudflare查询真实ip接口处查询真实ip
        # 如果查询到真实ip则返回ip值,如果没有查询到则返回0
        print("[*]现在从在线cloudflare类型cdn查询真实ip接口尝试获取真实ip")
        url = "http://www.crimeflare.com/cgi-bin/cfsearch.cgi"
        post_data = 'cfS=%s' % self.domain
        content = post_request(url, post_data)
        findIp = re.search("((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})""((\d{1,3}\.){3}\d{1,3})"r"((\d{1,3}\.){3}\d{1,3})", content)
        if findIp:
            return findIp.group(1)
        return 0


    def get_ip_value_from_ip138(self):
        print("3)尝试通过顶级域名寻找真实IP")
        #print('https://site.ip138.com/{}'.format(self.domain))
        headers = { 
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
        }
        domain = get_root_domain(self.domain)

        rep_test = requests.get('https://site.ip138.com/{}'.format(domain),timeout=15, verify=False, headers=headers).text
        allIP=re.findall("((\\d{1,3}\\.){3}\\d{1,3})",rep_test)
        ipList=[]
        index = 1
        for each in allIP:
            if index < 6:
                ipList.append(each[0])
            else:
                break
            index = index + 1
        
        ipList = list(set(ipList))#去重处理
        print(ipList)
        for each_ip in ipList:
            try:
                if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                    print(each_ip)
                    return each_ip
            except Exception as e:
                print("[-]访问 %s 失败,跳过该IP测试"%each_ip)
                continue
        return 0


    def get_ip_value_from_DNSDB(self):
        print("4)尝试通过DNS历史记录寻找真实IP")
        #print('https://site.ip138.com/{}'.format(self.domain))
        headers = { 
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
        }

        rep_test = requests.get('https://securitytrails.com/domain/{}/history/a'.format(self.domain),timeout=15, verify=False, headers=headers).text

        #rep_test_1 = requests.get('https://dns.bufferover.run/dns?q={}'.format(self.domain),timeout=15, verify=False, headers=headers).text

        allIP=re.findall("((\\d{1,3}\\.){3}\\d{1,3})",rep_test)
        #allIP_1 = re.findall("((\\d{1,3}\\.){3}\\d{1,3})",rep_test_1)

        ipList=[]
        index = 1
        index_1 =1
        for each in allIP:
            if index < 11:
                ipList.append(each[0])
            else:
                break
            index = index + 1
        '''
        for each_1 in allIP_1:
            if index_1 < 11:
                ipList.append(each_1[0])
            else:
                break
            index_1 = index_1 + 1
        '''
        ipList = list(set(ipList))#去重处理
        ipList.pop(0)#移除第一个元素
        print(ipList)
        for each_ip in ipList:
            try:
                if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                    print(each_ip)
                    return each_ip
            except Exception as e:
                print("[-]访问 %s 失败,跳过该IP测试"%each_ip)
                continue
        return 0
        


    def get_ip_value_from_fofa(self):
        import base64
        import urllib.parse
        print("5)尝试在FOFA上通过title寻找真实IP")
        headers = { 
            #'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
        }
        domain_title = "title=\"{}\"".format(self.domain_title)
        domain_title_base64 = base64.b64encode(domain_title.encode()).decode()
        #search_lan = 'https://fofa.so/result?q=title=\"{}\"&qbase64={}'.format(self.domain_title,domain_title_base64).replace('=','%3D')
        search_lan = 'https://fofa.so/result?q={}&qbase64={}'.format(urllib.parse.quote(self.domain_title),urllib.parse.quote(domain_title_base64))

        rep_test = requests.get(search_lan,timeout=15, verify=False, headers=headers).text
        #soup = BeautifulSoup(rep_test, 'lxml') #创建 beautifulsoup 对象
        #print(soup.find_all(class_='re-domain'))
        #for ip_domain in soup.find_all(class_='re-domain'):
        #    print(ip_domain.a.text.strip())
        allIP=re.findall("((\\d{1,3}\\.){3}\\d{1,3})",rep_test)
        ipList=[]
        index = 1
        for each in allIP:
            if index < 11:
                ipList.append(each[0])
            else:
                break
            index = index + 1
        
        ipList = list(set(ipList))#去重处理
        print(ipList)
        for each_ip in ipList:
            try:
                if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                    print(each_ip)
                    return each_ip
            except Exception as e:
                print("[-]访问 %s 失败,跳过该IP测试"%each_ip)
                continue
        return 0
        

    def get_ip_value_from_cert(self):
        print("6)尝试通过证书寻找真实IP")
        
        headers = { 
            'Connection': 'close',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'
        }


        rep_test = requests.get('https://crt.sh/?q={}'.format(self.domain),timeout=15, verify=False, headers=headers).text
        allIP=re.findall("((\\d{1,3}\\.){3}\\d{1,3})",rep_test)
        ipList=[]
        index = 1
        for each in allIP:
            if index < 11:
                ipList.append(each[0])
            else:
                break
            index = index + 1
        
        ipList = list(set(ipList))#去重处理
        print(ipList)
        for each_ip in ipList:
            try:
                if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                    print(each_ip)
                    return each_ip
            except Exception as e:
                print("[-]访问 %s 失败,跳过该IP测试"%each_ip)
                continue
        return 0
        


    def get_actual_ip_from_domain(self):
        # 尝试获得domain背后的真实ip,前提是domain有cdn
        # 如果找到了则返回ip,如果没有找到返回0
        print("[*]进入获取真实ip函数,认为每个domain都是有cdn的情况来处理")
        import socket
        has_cdn_value = self.domain_has_cdn()
        if has_cdn_value['has_cdn'] == 1:
            print("[*]检测到domain:%s的A记录不止一个,认为它有cdn" % self.domain)
            pass
        else:
            print("[*]Attention...!!! Domain doesn't have cdn,I will return the only one ip")
            true_ip = socket.gethostbyname_ex(self.domain)[2][0]
            return true_ip
        # 下面尝试通过cloudflare在线查询真实ip接口获取真实ip
        if has_cdn_value['is_cloud_flare'] == 1:
            #ip_value = self.get_ip_value_from_online_cloudflare_interface()
            ip_value = 0
            if ip_value != 0:
                return ip_value
            else:
                pass
        # 下面尝试通过可能存在的phpinfo页面获得真实ip

        for i in range(1):
            try:
                ip_from_phpinfo = self.get_domain_actual_ip_from_phpinfo()
                if ip_from_phpinfo == 0:
                    pass
                else:
                    return ip_from_phpinfo
            except Exception as e:
                print("发生异常,类型%s,跳过(1)测试方法"%type(e))
                #continue
            # 下面通过mx记录来尝试获得真实ip;寻找mx对应IP所在的C段
            try:
                result = self.check_if_mx_c_machines_has_actual_ip_of_domain()
                if result == 0:
                    pass
                else:
                    return result
            except Exception as e:
                print("发生异常,类型%s,跳过(2)测试方法"%type(e))
                #continue
            #下面通过查找顶级域名来获取真实IP
            try:
                result_1 = self.get_ip_value_from_ip138()
                if result_1 == 0:
                    pass
                else:
                    return result_1
            except Exception as e:
                print("发生异常,类型%s,跳过(3)测试方法"%type(e))
                #continue
            #下面通过DNS历史记录来获取真实IP
            try:
                result_2 = self.get_ip_value_from_DNSDB()
                if result_2 == 0:
                    pass
                else:
                    return result_2
            except Exception as e:
                print("发生异常,类型%s,跳过(4)测试方法"%type(e))
                #continue
            #下面通过FOFA搜索title查找真实IP
            try:
                result_3 = self.get_ip_value_from_fofa()
                if result_3 == 0:
                    pass
                else:
                    return result_3
            except Exception as e:
                print("发生异常,类型%s,跳过(5)测试方法"%type(e))
                #continue
            #下面通过证书查询真实IP
            try:
                result_4 = self.get_ip_value_from_cert()
                if result_4 == 0:
                    pass
                else:
                    return result_4
            except Exception as e:
                print("发生异常,类型%s,跳过(6)测试方法"%type(e))
                #continue
            break
        txt = """[*]很遗憾,在下认为%s有cdn,但是目前在下的能力没能获取它的真实ip,当前函数将返回0。
可以尝试通过下述网站查找：
https://censys.io/ipv4?q=
https://securitytrails.com/domain/www.baidu.com/history/a
https://crt.sh/
https://myssl.com/8000.webank.com?ip=
"""
        print(txt % self.domain)
        return 0
print("[*]用法：域名不能包含http和https字样，如果有端口直接在目标方框内加上端口")
def check(**kwargs):
    url = kwargs['url']
    Xcdn(url)
    #print(get_root_domain(url))


if __name__ == '__main__':
    import sys
    #domain=sys.argv[1]
    Xcdn("wygf.yftlc.com")

