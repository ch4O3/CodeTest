<h1 align="center" >Welcome to CodeTest</h1>

### :point_right:关于本项目

>本项目的主要目的: 针对日常收集的Python POC\EXP测试脚本，使用可视化界面统一执行入口，方便运行。
>
>本项目适合人群: 有Python基础的渗透测试人员（工具自带简易编辑器，可修改脚本内参数，重新加载后可灵活使用脚本进行测试）
>
>可视化界面开发库: Tkinter
>
>python版本: 3.5+

### :bulb:POC\EXP 参考链接

```
https://github.com/Ascotbe/Medusa
https://github.com/zhzyker/vulmap
https://github.com/Python3WebSpider/ProxyPool
```


### :book:使用说明

```
(一)下载文件
git clone https://github.com/codeyso/CodeTest.git
cd CodeTest

(二)安装依赖
pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
注意: ~\Python3\Lib\site-packages，找到这个路径，下面有一个文件夹叫做crypto,将小写c改成大写C
注意: 建议安装之前更新pip (python -m pip install --upgrade pip)

(三)使用工具
1) 双击 CodeTest.bat
2) pythonw3 -B CodeTest.pyw

(四)备注: 如果GitHub图片显示不出来，修改hosts
C:\Windows\System32\drivers\etc\hosts

在文件末尾添加
# GitHub Start 
192.30.253.112    Build software better, together 
192.30.253.119    gist.github.com
151.101.184.133    assets-cdn.github.com
151.101.184.133    raw.githubusercontent.com
151.101.184.133    gist.githubusercontent.com
151.101.184.133    cloud.githubusercontent.com
151.101.184.133    camo.githubusercontent.com
151.101.184.133    avatars0.githubusercontent.com
151.101.184.133    avatars1.githubusercontent.com
151.101.184.133    avatars2.githubusercontent.com
151.101.184.133    avatars3.githubusercontent.com
151.101.184.133    avatars4.githubusercontent.com
151.101.184.133    avatars5.githubusercontent.com
151.101.184.133    avatars6.githubusercontent.com
151.101.184.133    avatars7.githubusercontent.com
151.101.184.133    avatars8.githubusercontent.com

 # GitHub End
```


### :checkered_flag:模板
#### POC

```
def check(**kwargs):
	url = kwargs['url']#/*str*/
	print('输出结果')
	print(url)
	'''此处的返回状态码用于批量验证
	if True:
		return 1
	else:
		return
	'''
```


#### EXP

```
有专用的EXP生成界面
```


### :clipboard:功能界面介绍
#### 漏洞扫描界面
![漏洞扫描界面](https://github.com/codeyso/CodeTest/blob/master/img/1.png "漏洞扫描界面")

### :open_file_folder:使用示例
>案例参考：https://mp.weixin.qq.com/s/xwh81ZeE0Lgx-iIpqZI1_g

