from requests.packages import urllib3
from util.ExpRequest import ExpRequest,Output
urllib3.disable_warnings()

def check(**kwargs):
    try:
        output = Output('url_getTitle')
        exprequest = ExpRequest('url_getTitle', output)
        exprequest.get(kwargs['url'], retry_time=1)
        #print(exprequest.title)
        return exprequest.title
    except Exception as e:
        print('请求 %s 出现异常 %s'%(kwargs['url'], e))
        return type(e)

if __name__ == "__main__":
    pass
    






















