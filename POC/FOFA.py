import requests
from requests.packages import urllib3
urllib3.disable_warnings()
import base64
from lxml import etree

token = 'eyJhbGciOiJIUzUxMiIsImtpZCI6Ik5XWTVZakF4TVRkalltSTJNRFZsWXpRM05EWXdaakF3TURVMlkyWTNZemd3TUdRd1pUTmpZUT09IiwidHlwIjoiSldUIn0.eyJpZCI6MzU5NjYsIm1pZCI6MTAwMDI2MDc2LCJ1c2VybmFtZSI6InhreDUxOCIsImV4cCI6MTY0NjMzODk5NywiaXNzIjoicmVmcmVzaCJ9.Aqfrl1A0C-WE_T5ZER2eaylK0SdJfWULS8bbnvqWSjlyFzNubPJjbPCqU9nJdKZwTPPUUXp6WBVw33R_tCVAbg'

fofa_token = token
refresh_token = token

headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 7.1.2; PCRT00 Build/N2G48H; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.158 Safari/537.36 fanwe_app_sdk sdk_type/android sdk_version_name/4.0.1 sdk_version/2020042901 screen_width/720 screen_height/1280',
    }
print('''[*]请登录后使用, fofa查询语法:
+--------------------------+---------------------------------------------+
| 例句                     | 用途说明                                     |
+--------------------------+---------------------------------------------+
| title="beijing"          | 从标题中搜索“北京”                           
| header="elastic"         | 从http头中搜索“elastic”                     
| body="phpcms"            | 从html正文中搜索“网络空间测绘”               
| domain="qq.com"          | 搜索根域名带有qq.com的网站                   
| icp="ICP-030173号"       | 查找备案号为“京ICP证030173号”的网站          
| host=".gov.cn"           | 从url中搜索”.gov.cn”                        
| port="6379"              | 查找对应“6379”端口的资产                    
| ip="1.1.1.1"             | 从ip中搜索包含“1.1.1.1”的网站               
| ip="220.181.111.1/24"    | 查询IP为“220.181.111.1”的C网段资产          
| protocol="quic"          | 查询quic协议资产                            
| country="CN"             | 搜索指定国家(编码)的资产                    
| app="Microsoft-Exchange" | 搜索Microsoft-Exchange设备                  
| cert="baidu"             | 搜索证书(https或者imaps等)中带有baidu的资产 
| status_code="402"        | 查询服务器状态为“402”的资产                 
+--------------------------+---------------------------------------------+
''')
#获取爬取的页面数量
def pag_num_fun(word):
    print("[*]开始获取查询的页面数量...")
    #查询词进行baase64编码
    s = (base64.b64encode(word.encode('utf-8'))).decode('utf-8')
    #查询的url
    url = f"https://fofa.info/result?qbase64={s}&page=1&page_size=10"
    print("[*]查询地址为：",url)
    #获取页面源码
    text = requests.get(url=url,headers=headers,verify=False,timeout=20,cookies={'fofa_token':fofa_token,'refresh_token':refresh_token}).text
    #获取爬取目标的页面数量
    tree = etree.HTML(text)
    try:
    #pag_num:获取到的页面总数量
        pag_num = tree.xpath('//div[@id="__layout"]//div[@class="pagFooter"]/div[@class="el-pagination"]/ul[@class="el-pager"]/li/text()')[-1]
    except Exception as error:
        print('[-]查询目标无结果,请确认查询语法.详细错误为：%s'%type(error))
        #return
        #raise Exception("")
    print('[*]FOFA爬取页面数量为: '+ pag_num)
    return pag_num

#定义爬取页面ip的函数
def fofa(word, pag_num, num = 5):
    index = 0#实际页数
    s = (base64.b64encode(word.encode('utf-8'))).decode('utf-8')
    ip_list = []  #定义存放所有ip的列表
    for i in range(1,num+1):
        #获取页面源码
        url = f"https://fofa.info/result?page={i}&qbase64={s}"
        try:
            text = requests.get(url=url,headers=headers,verify=False,timeout=10,cookies={'fofa_token':fofa_token,'refresh_token':refresh_token}).text
        except Exception as error:
            print("fofa函数中，获取页面源码时发生错误，错误所在地为text变量。详细错误为：%s"%type(error))
            continue
        tree = etree.HTML(text)
        #提取一个页面所有ip地址
        try:
            r = tree.xpath('//div[@id="__layout"]//div[@class="showListsContainer"]/div[@class="rightListsMain"]//a[@target="_blank"]/@href')
            #title = tree.xpath('//div[@class="contentLeft"]/p[1]/text()')
            #country = tree.xpath('//div[@class="contentLeft"]/p[3]/a[@class="jumpA"]/text()')
        except Exception as error:
            print('fofa函数中，提取页面ip地址时发生错误，错误所在地为r变量。详细错误为：%s'%error)
            return
        if len(r) == 0:
            break
        for m in range(len(r)):
            if "//" in r[m]:
                #将ip地址保存到列表中
                ip_list.append(r[m])
                #ip_list.append(r[m]+'  '+ country[m])
                #ip_list.append(r[m] +'  '+ title[m] +'  '+ country[m])
            else:
                pass
        index = index + 1
        print(f'[*]第{i}页爬取完毕！')
    ip_list_new = list(set(ip_list))    #将ip地址去重，然后进行保存
    if int(pag_num) > index:
        print('[*]提示: 输入登录后的cookie即可获取更多数据哦!')
    print('[+]FOFA收集 %s 页结果如下, 总计 [%s]'%(str(index),len(ip_list_new)))
    for url in ip_list_new:
        print(url)

print("用法: 在目标处输入查询语法,需要编辑源码修改refresh_token (普通用户默认查询5页)")
def check(**kwargs):
    try:
        pag_num = pag_num_fun(kwargs['url'])
        fofa(kwargs['url'], pag_num)
    except Exception as e:
        print(type(e))

if __name__ == '__main__':
    pag_num = pag_num_fun('app=\"Shiro权限管理系统\"')
    fofa('app=\"Shiro权限管理系统\"', pag_num)










































