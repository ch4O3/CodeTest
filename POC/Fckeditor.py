import requests,time
from requests.packages import urllib3
from CodeTest import color
urllib3.disable_warnings()

#敏感信息路径查找
Fck_path_list = ['/editor/dialog/fck_about.html','/_whatsnew.html','/editor/filemanager/browser/default/connectors/test.html','/editor/filemanager/upload/test.html','/editor/filemanager/connectors/test.html','/editor/filemanager/connectors/uploadtest.html','/_samples/default.html','/_samples/asp/sample01.asp','/_samples/asp/sample02.asp','/_samples/asp/sample03.asp','/_samples/asp/sample04.asp','/editor/.htm','/editor/fckdialog.html','/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/connectors/jsp/connector.jsp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/php/connector.php','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/asp/connector.asp','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/aspx/connector.aspx','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/jsp/connector.jsp','/editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/aspx/connector.Aspx','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/php/connector.php','/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=File&CurrentFolder=/shell.asp&NewFolderName=z.asp','/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=Image&CurrentFolder=/shell.asp&NewFolderName=z&uuid=1244789975684','/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=CreateFolder&CurrentFolder=/&Type=Image&NewFolderName=shell.asp','/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=CreateFolder&Type=Image&CurrentFolder=../../../&NewFolderName=shell.asp','/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=e:/']
VUL_LIST = []

"""
:查找spring敏感路径泄露信息
"""
def spider(urls,time):
    """
    :return:VUL_LIST
    """
    s = requests.session()
    s.trust_env = False
    s.verify = False
    status_code = None
    s.headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36'
    }
    for path in Fck_path_list:
        urls_path = urls + path
        #urls = 'http://110.53.243.248:9006/swagger-ui.html'
        try:
            content = s.get(urls_path, headers=s.headers, timeout=time, allow_redirects=False)
            status_code = content.status_code
            if status_code != 404:
                VUL_LIST.append(path)
                color('[+] %s %s'%(urls_path,str(status_code)),'green')
            else:
                color('[-] %s %s'%(urls_path,str(status_code)),'red')
        except Exception as e:
            print('[-] 请求 %s 出现异常 %s'%(urls_path,type(e)))
            continue
    return VUL_LIST

def check(**kwargs):
    try:
        urls = kwargs['url']#/*str*/
        urls = urls.strip('/')
        VUL_LIST = spider(urls, 3)

        if '/jolokia' in VUL_LIST or '/actuator/jolokia' in VUL_LIST:
            print('https://github.com/LandGrey/SpringBootVulExploit')
            print('0x03：获取被星号脱敏的密码的明文 (方法一)')
            print('0x04：jolokia logback JNDI RCE')
            print('0x05：jolokia Realm JNDI RCE')

        elif '/env' in VUL_LIST and '/refresh' in VUL_LIST:
            print('https://github.com/LandGrey/SpringBootVulExploit')
            print('0x04：获取被星号脱敏的密码的明文 (方法二)')
            print('0x05：获取被星号脱敏的密码的明文 (方法三)')
            print('0x02：spring cloud SnakeYAML RCE')
            print('0x03：eureka xstream deserialization RCE')
            print('0x06：h2 database query RCE')
            print('0x08：mysql jdbc deserialization RCE')

        elif '/heapdump' in VUL_LIST or '/actuator/heapdump' in VUL_LIST:
            print('https://github.com/LandGrey/SpringBootVulExploit')
            print('0x06：获取被星号脱敏的密码的明文 (方法四)')
        else:
        	print('[-] 未找到相关漏洞信息, 请参阅: https://github.com/LandGrey/SpringBootVulExploit')
        #print(VUL_LIST)
        return VUL_LIST
    except Exception as e:
        print('脚本执行出错 %s'%e)

if __name__ == "__main__":
    a = check(**{'url':'http://www.baidu.com'})
    #print(a)








