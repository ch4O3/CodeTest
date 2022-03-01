# -*- coding:UTF-8 -*-
from tkinter import ttk,messagebox,scrolledtext,Toplevel,Tk,Menu,Frame,Button,Label,Entry,Text,Spinbox,Scrollbar,Checkbutton,LabelFrame,PanedWindow,IntVar,Listbox,Canvas,filedialog,PhotoImage
from tkinter import HORIZONTAL,LEFT,RIGHT,YES,BOTH,INSERT,END,SINGLE,VERTICAL,Y,X,S,W,E,N
from tkinter.filedialog import askopenfilename
from requests_toolbelt.utils import dump
#from keyword import kwlist
from exp10it import seconds2hms
from os.path import isfile,isdir
from colorama import init, Fore, Back, Style
from jinja2 import Environment, PackageLoader
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor,wait,as_completed,ALL_COMPLETED

from itertools import repeat
from urllib3.util import retry
from openpyxl import Workbook
from ClassCongregation import ysoserial_payload,Sql_scan,TextRedirector,color,open_html
from Proxy.proxyFetcher import ProxyFetcher
from Proxy.helper.check import DoValidator,Checker
from Proxy.helper.proxy import Proxy as Proxy_cls
from textwrap import wrap,fill
import util.globalvar as GlobalVar
import os,sys,time,socket,socks,datetime,queue
import importlib,glob,requests,binascii,re
import threading,ast,math,json,base64
import urllib3, pymysql
import inspect
import ctypes
import string
import prettytable as pt

#去除错误警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#主界面类
class MyGUI:
    vuln = None #POC界面当前加载的对象
    now_text = '' #存放多目标的地方
    threadList = [] #填充线程列表,创建多个存储POC脚本的界面, 默认为1, 2, 3, 4
    threadLock = threading.Lock() #线程锁
    scripts = [] #poc下的脚本文件列表
    wait_index = 0 #用于wait_running函数
    Checkbutton_text = '' #选中的checkbutton,代表执行的POC脚本名称
    var = [] #保存多个checkbutton关联的变量
    row = 1 #用于生成checkbutton处的定位
    vul_name = ''#当前脚本名称
    wb = None#当前结果文件
    ws = None#excel表格
    wbswitch = ''#开关
    def __init__(self):#初始化窗体对象
        self.root = Tk()
        #self.root.lift()
        self.root.iconbitmap('python.ico')
        self.title = self.root.title('POC检测')#设置title
        self.size = self.root.geometry('960x650+400+50')#设置窗体大小，960x650是窗体大小，400+50是初始位置
        self.exchange = self.root.resizable(width=False, height=False)#不允许扩大
        self.root.columnconfigure(0, weight=1)
        #对象属性参数字典
        self.frms = self.__dict__
        #创建顶级菜单
        self.menubar = Menu(self.root)
        self.menubar_1 = Menu(self.root,tearoff=False)#创建一个菜单
        
        #顶级菜单添加一个子菜单
        self.menubar1 = Menu(self.root,tearoff=False)
        self.menubar1.add_command(label = "项目根目录", command=lambda:LoadCMD('/'))
        self.menubar1.add_command(label = "POC目录", command=lambda:LoadCMD('/POC'))
        self.menubar1.add_command(label = "EXP目录", command=lambda:LoadCMD('/EXP'))
        self.menubar1.add_command(label = "Shell目录", command=lambda:LoadCMD('/execScripts'))
        self.menubar1.add_command(label = "Result目录", command=lambda:LoadCMD('/result'))
        self.menubar1.add_command(label = "Log目录", command=lambda:LoadCMD('/log'))
        self.menubar1.add_command(label = "Payload_html", command=lambda:LoadCMD('/payload_html'))
        self.menubar.add_cascade(label = "打开文件", menu = self.menubar1)

        #顶级菜单增加一个普通的命令菜单项
        #self.menubar.add_command(label = "Ysoserial", command=lambda :Ysoserial_ter(gui.root))
        self.menubar.add_command(label = "设置代理", command=lambda :TopProxy(gui.root))
        self.menubar.add_command(label = "免费代理池", command=lambda :Proxy_pool(gui.root))
        self.menubar.add_command(label = "TCP数据调试", command=lambda :Data_debug(gui.root))
        #显示菜单
        self.root.config(menu = self.menubar)
        

    #创造幕布
    def CreateFrm(self):
        self.frmTOP = Frame(self.root, width=960 , height=25, bg='whitesmoke')
        self.frmPOC = Frame(self.root, width=960 , height=600, bg='white')
        self.frmEXP = Frame(self.root, width=960 , height=610, bg='white')
        self.frmCheck = Frame(self.root, width=960 , height=610, bg='white')
        self.frmNote = Frame(self.root, width=960 , height=610, bg='red')
        #self.frmDebug = Frame(self.root, width=960 , height=610, bg='red')

        self.frmTOP.grid(row=0, column=0, padx=2, pady=2)
        self.frmPOC.grid(row=1, column=0, padx=2, pady=2)
        #self.frmMain.destroy()

        #创建按钮
        self.frmTOPButton1 = Button(self.frmTOP, text='漏洞扫描', width = 10, command=POC)
        self.frmTOPButton2 = Button(self.frmTOP, text='漏洞利用', width = 10, command=EXP)
        self.frmTOPButton3 = Button(self.frmTOP, text='漏洞测试', width = 10, command=Check)
        #self.frmTOPButton4 = Button(self.frmTOP, text='漏洞笔记', width = 10, command=shownote)
        #self.frmTOPButton5 = Button(self.frmTOP, text='数据调试', width = 10, command=data_debug)
        self.frmTOPButton1.grid(row=0,column=0,padx=1, pady=1)
        self.frmTOPButton2.grid(row=0,column=2,padx=1, pady=1)
        self.frmTOPButton3.grid(row=0,column=3,padx=1, pady=1)
        #self.frmTOPButton4.grid(row=0,column=4,padx=1, pady=1)
        #self.frmTOPButton5.grid(row=0,column=4,padx=1, pady=1)
        
        self.frmTOP.grid_propagate(0)
        self.frmPOC.grid_propagate(0)
        self.frmEXP.grid_propagate(0)
        self.frmCheck.grid_propagate(0)
        #self.frmDebug.grid_propagate(0)

        #定义frame
        self.frmA = Frame(self.frmPOC, width=720, height=30,bg='white')#目标，输入框
        self.frmB = Frame(self.frmPOC, width=720, height=500, bg='white')#输出信息
        self.frmC = Frame(self.frmPOC, width=720, height=40, bg='white')#功能按钮
        #self.frmD = Frame(self.root, width=250, height=520)#POC
        #创建帆布
        #self.canvas = Canvas(self.frmPOC,width=300,height=590,scrollregion=(0,0,550,550)) #创建canvas
        #在帆布上创建frmD
        self.frmE = Frame(self.frmPOC, width=230, height=40,bg='white')
        #创建多个frm, 方便切换存储POC
        self.frms['frmD_'+str(1)] = Frame(self.frmPOC,width=230,height=500,bg='whitesmoke')
        self.frms['frmD_'+str(2)] = Frame(self.frmPOC,width=230,height=500,bg='whitesmoke')
        self.frms['frmD_'+str(3)] = Frame(self.frmPOC,width=230,height=500,bg='whitesmoke')
        self.frms['frmD_'+str(4)] = Frame(self.frmPOC,width=230,height=500,bg='whitesmoke')
        for i in range(1,5):
            #self.frms['frmD_'+str(i)].grid(row=1, column=1, padx=2, pady=2)
            self.frms['frmD_'+str(i)].grid_propagate(0)

        #self.canvas.create_window((0,0), window=self.frmD)#create_window
        self.frmF = Frame(self.frmPOC, width=230, height=40,bg='white')
        #表格布局
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=1, column=0, padx=2, pady=2)
        self.frmC.grid(row=2, column=0, padx=2, pady=2)
        #self.canvas.grid(row=1, column=1, rowspan=3, padx=2, pady=2)
        self.frmE.grid(row=0, column=1, padx=2, pady=2)
        self.frmD_1.grid(row=1, column=1, padx=2, pady=2)
        self.frmF.grid(row=2, column=1, padx=2, pady=2)
        #固定大小
        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        self.frmC.grid_propagate(0)
        self.frmE.grid_propagate(0)
        self.frmF.grid_propagate(0)
        #self.canvas.grid_propagate(0)
        

    #创造第一象限
    def CreateFirst(self):
        self.LabA = Label(self.frmA, text='目标')#显示
        self.EntA = Entry(self.frmA, width='60',highlightcolor='red', highlightthickness=1,font=("consolas",10)) #接受输入控件

        self.LabA2 = Label(self.frmA, text='运行状态')#显示
        #self.EntA2 = Entry(self.frmA, width='7',highlightcolor='red', highlightthickness=1,font=("consolas",10)) #接受输入控件
        self.TexA2 = Text(self.frmA, font=("consolas",10), width=2, height=1)

        self.ButtonA = Button(self.frmA, text='...', width=5, command=lambda :Loadfile(self.root)) #批量导入文件

        #线程池数量
        self.LabA3 = Label(self.frmA, text='线程(1~10)')
        self.b1 = Spinbox(self.frmA,from_=1,to=10,wrap=True,width=3,font=("consolas",10),textvariable=Ent_A_Top_thread)

        #表格布局
        self.LabA.grid(row=0,column=0,padx=2, pady=2)
        self.EntA.grid(row=0,column=1,padx=2, pady=2)

        self.LabA2.grid(row=0,column=2,padx=2, pady=2)
        self.TexA2.grid(row=0,column=3,padx=2, pady=2)

        self.ButtonA.grid(row=0,column=4,padx=2, pady=2)

        self.LabA3.grid(row=0,column=5,padx=2, pady=2)
        self.b1.grid(row=0,column=6,padx=2, pady=2)
        #self.LabA3.grid(row=1,column=0)
        #self.EntA3.grid(row=1,column=1)
        self.TexA2.configure(state="disabled")
        #self.ButtonA1.grid(row=1,column=2,padx=4, pady=4)Times
    #创造第二象限
    def CreateSecond(self):
        self.TexB = Text(self.frmB, font=("consolas",10), width=100, height=32)
        self.ScrB = Scrollbar(self.frmB)  #滚动条控件
        #进度条控件
        #self.p1B = Label(self.frmB, text='进度条:')#显示

        self.p1 = ttk.Progressbar(self.frmB, length=705, mode="determinate",maximum=705,orient=HORIZONTAL)
        #表格布局
        self.TexB.grid(row=1,column=0)
        self.ScrB.grid(row=1,column=1, sticky=S + W + E + N)#允许拖动
        self.ScrB.config(command=self.TexB.yview)
        self.TexB.config(yscrollcommand=self.ScrB.set)
        #进度条布局
        #self.p1B.grid(row=2,column=1)
        self.p1.grid(row=2,column=0,sticky=W)

    #创造第三象限
    def CreateThird(self):
        self.ButtonC1 = Button(self.frmC, text='验 证', width = 10, command=lambda :self.thread_it(self.BugTest,**
        {
            'url' : self.EntA.get(),
            'pool' : int(Ent_A_Top_thread.get())
            }
        ))
        self.ButtonC2 = Button(self.frmC, text='终 止', width = 10, command=lambda :self.stop_thread())
        self.ButtonC3 = Button(self.frmC, text='清空信息', width = 15, command=lambda :delText(gui.TexB))
        self.ButtonC4 = Button(self.frmC, text='重新载入当前POC', width = 15, command=ReLoad)
        self.ButtonC5 = Button(self.frmC, text='当前进程运行状态', width = 15, command=ShowPython)
        self.ButtonC6 = Button(self.frmC, text='保存批量检测结果', width = 15, command=save_result)
        #self.LabCA    = Label(self.frmC, text='当前运行状态')
        #self.TexCA    = Text(self.frmC, font=("consolas",10), width=2, height=1)

        #self.TexCA.tag_add("here", "1.0","end")
        #self.TexCA.tag_config("here", background="blue")
        #self.TexCA.configure(state="disabled")
        #表格布局
        self.ButtonC1.grid(row=0, column=0,padx=2, pady=2)
        self.ButtonC2.grid(row=0, column=1,padx=2, pady=2)
        self.ButtonC3.grid(row=0, column=2,padx=2, pady=2)
        self.ButtonC4.grid(row=0, column=3,padx=2, pady=2)
        self.ButtonC5.grid(row=0, column=4,padx=2, pady=2)
        self.ButtonC6.grid(row=0, column=5,padx=2, pady=2)
        #self.LabCA.grid(row=0, column=5,padx=2, pady=2)
        #self.TexCA.grid(row=0, column=6,padx=2, pady=2)
    #创造第四象限
    def CreateFourth(self):
        self.ButtonE1 = Button(self.frmE, text='加载POC', width = 8, command=LoadPoc)
        self.ButtonE2 = Button(self.frmE, text='编辑文件', width = 8, command=lambda:Topfile(gui.root,MyGUI.Checkbutton_text,'1',MyGUI.vuln))
        self.ButtonE3 = Button(self.frmE, text='打开脚本目录', width = 10, command=lambda:LoadCMD('/POC'))

        self.ButtonE1.grid(row=0, column=0,padx=2, pady=2)
        self.ButtonE2.grid(row=0, column=1,padx=2, pady=2)
        self.ButtonE3.grid(row=0, column=2,padx=2, pady=2)

        #self.vbar = Scrollbar(self.canvas, orient=VERTICAL) #竖直滚动条
        #self.vbar.grid(row=1, sticky=S + W + E + N)#允许拖动
        #self.vbar.config(command=self.canvas.yview)
        #self.canvas.config(yscrollcommand = self.vbar.set)

    def CreateFivth(self):
        self.ButtonF1 = Button(self.frmF, text='1', width = 6, command=lambda:Area_POC(1))
        self.ButtonF2 = Button(self.frmF, text='2', width = 6, command=lambda:Area_POC(2))
        self.ButtonF3 = Button(self.frmF, text='3', width = 6, command=lambda:Area_POC(3))
        self.ButtonF4 = Button(self.frmF, text='4', width = 6, command=lambda:Area_POC(4))

        self.ButtonF1.grid(row=0, column=0, padx=3, pady=3)
        self.ButtonF2.grid(row=0, column=1, padx=3, pady=3)
        self.ButtonF3.grid(row=0, column=2, padx=3, pady=3)
        self.ButtonF4.grid(row=0, column=3, padx=3, pady=3)
    
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs,name='执行函数子线程',daemon=True)
        self.t.start()           # 启动
    
    def stop_thread(self):
        try:
            _async_raise(self.t.ident, SystemExit)
            #self.wait_running_job.stop()
            print("[*]已停止运行")
        except Exception as e:
            messagebox.showinfo('提示','没有正在运行的进程!')
        finally:
            gui.TexA2.delete('1.0','end')
            gui.TexA2.configure(state="disabled")

    def BugTest(self,**kwargs):
        #kwargs = {url,port,file_list,pool}
        #url:str
        #port:str
        #file_list:str
        #pool:str
        if MyGUI.vuln == None:
            messagebox.showinfo(title='提示', message='还未选择模块')
            return

        MyGUI.vul_name = MyGUI.vuln.__name__.replace('POC.','')
        #进度条初始化
        gui.p1["value"] = 0
        gui.root.update()

        MyGUI.wbswitch = 'false'
        start = time.time()
        color(Separator_(MyGUI.vul_name),'blue')
        #now = datetime.datetime.now()
        #print("["+str(now)[11:19]+"] " + "[*] 开始执行测试")
        print("[*]开始执行测试")

        if kwargs['url']:
            #进入单模块测试功能
            try:
                self.t2 = threading.Thread(target=wait_running,name='运行状态子线程',daemon=True)
                self.t2.start()
                MyGUI.vuln.check(**kwargs)
            except Exception as e:
                print('出现错误: %s'%e)
            finally:
                _async_raise(self.t2.ident, SystemExit)
                gui.TexA2.delete('1.0','end')
                gui.TexA2.configure(state="disabled")
            end = time.time()
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*] 共花费时间：{} 秒".format(seconds2hms(end - start)))
            print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
            #print(MyGUI.vuln.__name__)
            return
        elif MyGUI.now_text.strip('\n'):
            #进入多目标测试功能
            file_list = [i for i in MyGUI.now_text.split("\n") if i!='']#去空处理
            file_len = len(file_list)
            flag = round(705/file_len, 2)#每执行一个任务增长的长度

            executor = ThreadPoolExecutor(max_workers = int(kwargs['pool']))
            url_list = []#存储目标列表
            result_list = []#存储结果列表

            for url in file_list:
                args = {'url':url}
                url_list.append(args)
            try:
                for data in executor.map(lambda kwargs: MyGUI.vuln.check(**kwargs), url_list):
                    if type(data) == list:#如果结果是列表,去重一次
                        data = list(set(data))
                    result_list.append(data)#汇聚结果
                    MyGUI.threadLock.acquire()
                    gui.p1["value"] = gui.p1["value"]+flag#进度条
                    gui.root.update()
                    MyGUI.threadLock.release()
                #根据结果生成表格
                index_list = [i+1 for i in range(len(url_list))]
                print_result = zip(index_list, file_list, result_list)#合并列表
                tb = pt.PrettyTable()
                tb.field_names = ["Index", "URL", "Result"]
                tb.align['URL'] = 'l'
                tb.align['Result'] = 'l'
                #保存结果
                MyGUI.wbswitch = 'true'
                #构造初始环境
                MyGUI.wb = Workbook()#当前结果文件
                MyGUI.ws = MyGUI.wb.active#excel表格
                MyGUI.ws.append(['Index','URL', 'Result'])
                index = 1
                #输出结果
                for i in print_result:
                    MyGUI.ws.append(i)
                    tb.add_row(i)
                    index += 1
                print(tb)
                #end = time.time()
                #print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
            except Exception as e:
                print('执行脚本出现错误: %s ,建议在脚本加上异常处理!'%type(e))
                gui.p1["value"] = 705
                gui.root.update()
            finally:
                end = time.time()
                #now = datetime.datetime.now()
                #print("["+str(now)[11:19]+"] " + "[*] 共花费时间：{} 秒".format(seconds2hms(end - start)))
                print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
        #没有输入测试目标
        else:
            color('[*]请输入目标URL!','red')
            color('[*]请输入目标URL!','yellow')
            color('[*]请输入目标URL!','blue')
            color('[*]请输入目标URL!','green')
            color('[*]请输入目标URL!','orange')
            color('[*]请输入目标URL!','pink')
            color('[*]请输入目标URL!','cyan')

    #开始循环
    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.CreateFivth()
        ###EXP界面组件创建
        #exp = MyEXP(self.root,self.frmEXP)
        #exp.start()
        ###EXP界面组件创建

class TopProxy():
    def __init__(self,root):
        global variable_dict

        self.Proxy = Toplevel(root)
        self.Proxy.title("代理服务器设置")
        self.Proxy.geometry('300x300+650+150')

        self.frmA = Frame(self.Proxy, width=300, height=50,background='whitesmoke')
        self.frmB = Frame(self.Proxy, width=300, height=90,background='whitesmoke')
        self.frmC = Frame(self.Proxy, width=300, height=130,background='whitesmoke')
        self.frmA.grid(row=0, column=0, padx=10, pady=10)
        self.frmB.grid(row=1, column=0, padx=2, pady=2)
        self.frmC.grid(row=2, column=0, padx=2, pady=2)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        self.frmC.grid_propagate(0)

        self.button1 = Checkbutton(self.frmA,text="启用",command=lambda:self.Yes(),variable=variable_dict["Proxy_CheckVar1"])
        self.button2 = Checkbutton(self.frmA,text="禁用",command=lambda:self.No(),variable=variable_dict["Proxy_CheckVar2"])
        
        self.button1.grid(row=0, column=0)
        self.button2.grid(row=0, column=1)

        self.LabA = Label(self.frmB, text='类   型')#显示
        self.comboxlistA = ttk.Combobox(self.frmB,width=12,textvariable=variable_dict["PROXY_TYPE"],state='readonly') #接受输入控件
        self.comboxlistA["values"]=("HTTP","HTTPS","HTTP/HTTPS","SOCKS5","SOCKS4")
        #self.comboxlistA.current(0)

        self.LabB = Label(self.frmB, text='IP地址')#显示
        self.EntB = Entry(self.frmB, width='30',textvariable=variable_dict["Proxy_addr"]) #接受输入控件

        self.LabC = Label(self.frmB, text='端   口')#显示
        self.EntC = Entry(self.frmB, width='30',textvariable=variable_dict["Proxy_port"]) #接受输入控件

        #self.LabD = Label(self.frmB, text='用户名:')#显示
        #self.EntD = Entry(self.frmB, width='30') #接受输入控件

        #self.LabE = Label(self.frmB, text='密码:')#显示
        #self.EntE = Entry(self.frmB, width='30') #接受输入控件

        self.LabA.grid(row=0, column=0,padx=2, pady=2,sticky=W)
        self.comboxlistA.grid(row=0, column=1,padx=2, pady=2,sticky=W)

        self.LabB.grid(row=1, column=0,padx=2, pady=2,sticky=W)
        self.EntB.grid(row=1, column=1,padx=2, pady=2)

        self.LabC.grid(row=2, column=0,padx=2, pady=2,sticky=W)
        self.EntC.grid(row=2, column=1,padx=2, pady=2)

        self.buttonD = Button(self.frmC,text='还原',width=20,command=self.old)
        self.buttonE = Button(self.frmC,text='输出代理',width=20,command=self.show_proxy)
        self.buttonD.grid(row=0,column=0,padx=2,pady=2)
        self.buttonE.grid(row=1,column=0,padx=2,pady=2)
        #self.LabD.grid(row=3, column=0,padx=2, pady=2)
        #self.EntD.grid(row=3, column=1,padx=2, pady=2)

        #self.LabE.grid(row=4, column=0,padx=2, pady=2)
        #self.EntE.grid(row=4, column=1,padx=2, pady=2)

    def Yes(self):
        variable_dict["Proxy_CheckVar2"].set(0)
        if variable_dict["Proxy_CheckVar1"].get() == 1:

            proxy_str = variable_dict["PROXY_TYPE"].get()
            ip = self.EntB.get() if self.EntB.get() else None
            port = self.EntC.get() if self.EntC.get() else None
            #username = self.EntD.get() if self.EntD.get() else None
            #passwd = self.EntE.get() if self.EntE.get() else None

            if proxy_str == "HTTP":
                os.environ['HTTP_PROXY'] = ip+':'+port
            elif proxy_str == "HTTPS":
                os.environ['HTTPS_PROXY'] = ip+':'+port
            elif proxy_str == "HTTP/HTTPS":
                os.environ['HTTP_PROXY'] = ip+':'+port
                os.environ['HTTPS_PROXY'] = ip+':'+port
            else:
                if proxy_str == "SOCKS4":
                    proxy_type = socks.SOCKS4
                elif proxy_str == "SOCKS5":
                    proxy_type = socks.SOCKS5
                socks.set_default_proxy(proxy_type, ip, int(port))
                socket.socket = socks.socksocket
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*] 设置代理成功")
            print('[*]设置代理成功')
        else:
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*] 取消代理")
            print('[*]取消代理')

        
    def No(self):
        variable_dict["Proxy_CheckVar1"].set(0)
        if variable_dict["Proxy_CheckVar2"].get() == 1:
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            print('[*]禁用代理')
            
    def old(self):
        variable_dict["Proxy_CheckVar1"].set(0)
        variable_dict["Proxy_CheckVar2"].set(0)
        variable_dict["PROXY_TYPE"].set('HTTP/HTTPS')
        variable_dict["Proxy_addr"].set('127.0.0.1')
        variable_dict["Proxy_port"].set('8080')
        socks.set_default_proxy(None)
        socket.socket = socks.socksocket
        os.environ['HTTP_PROXY'] = ''
        os.environ['HTTPS_PROXY'] = ''
        
    def show_proxy(self):
        print('[*]HTTP_PROXY: '+os.environ['HTTP_PROXY'])
        print('[*]HTTPS_PROXY: '+os.environ['HTTPS_PROXY'])
        
        
class Ysoserial_ter():
    ysotype_list = ['-jar','-cp']
    ysoclass_list = ['BeanShell1','C3P0','Clojure','CommonsBeanutils1','CommonsCollections1','CommonsCollections2',
        'CommonsCollections3','CommonsCollections4','CommonsCollections5','CommonsCollections6','CommonsCollections7',
        'CommonsCollections8','CommonsCollections9','CommonsCollections10','FileUpload1','Groovy1','Hibernate1','Hibernate2',
        'JBossInterceptors1','JRMPClient','JRMPListener','JSON1','JavassistWeld1','Jdk7u21','Jython1','MozillaRhino1','MozillaRhino2',
        'Myfaces1','Myfaces2','ROME','ShiroCheck','Spring1','Spring2','Spring3','URLDNS','Vaadin1','Wicket1']

    ysoother_list = ['ysoserial.my.DirectiveProcessor','ysoserial.Deserializer']
    java_payload = None
    def __init__(self,root):
        self.yso = Toplevel(root)
        self.yso.title("ysoserial代码生成")
        self.yso.geometry('950x600+650+150')
        self.exchange = self.yso.resizable(width=False, height=False)#不允许扩大

        
        self.frmA = Frame(self.yso, width=945, height=90,bg="white")
        self.frmB = Frame(self.yso, width=945, height=500,bg="white")
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=1, column=0, padx=2, pady=2)
        #self.frmB.place(relx = 0, rely = 0)
        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)

        #参数配置,上半区
        self.frame_1 = LabelFrame(self.frmA, text="参数配置", labelanchor="nw", width=940, height=85, bg='whitesmoke')
        self.frame_1.grid(row=0, column=0, padx=2, pady=2)
        self.frame_1.grid_propagate(0)

        self.frame_1_A = Frame(self.frame_1, width=930, height=30,bg="whitesmoke")
        self.frame_1_B = Frame(self.frame_1, width=930, height=30,bg="whitesmoke")

        self.frame_1_A.grid(row=0, column=0, padx=1, pady=1)
        self.frame_1_B.grid(row=1, column=0, padx=1, pady=1)

        self.frame_1_A.grid_propagate(0)
        self.frame_1_B.grid_propagate(0)

        #第一行
        self.label_1 = Label(self.frame_1_A, text="ysoserial:")
        self.comboxlist_A_type = ttk.Combobox(self.frame_1_A,width='10',textvariable=Ent_yso_Top_type,state='readonly',font=("consolas",10))
        self.comboxlist_A_type["values"] = tuple(Ysoserial_ter.ysotype_list)
        self.comboxlist_A_type.bind("<<ComboboxSelected>>", self.change_type)

        self.comboxlist_A_class = ttk.Combobox(self.frame_1_A,width='35',textvariable=Ent_yso_Top_class,state='readonly',font=("consolas",10))
        self.comboxlist_A_class["values"] = tuple(Ysoserial_ter.ysoclass_list)
        self.comboxlist_A_class.bind("<<ComboboxSelected>>", self.change_class)

        self.label_1.grid(row=0,column=0,padx=2, pady=2, sticky=W)
        self.comboxlist_A_type.grid(row=0,column=1,padx=2, pady=2, sticky=W)
        self.comboxlist_A_class.grid(row=0,column=2,padx=2, pady=2, sticky=W)

        #第二行
        self.label_2 = Label(self.frame_1_B, text="inputcmds:")
        self.EntA_2 = Entry(self.frame_1_B, width='110', highlightcolor='red', highlightthickness=1,textvariable=Ent_yso_Top_cmd,font=("consolas",10))
        self.button_2 = Button(self.frame_1_B, text="Exploit", width=10, command=self.Exploit)

        self.label_2.grid(row=0,column=0,padx=2, pady=2,sticky=W)
        self.EntA_2.grid(row=0,column=1,padx=2, pady=2,sticky=W)
        self.button_2.grid(row=0,column=2,padx=2, pady=2,sticky=W)


        #下半区
        self.TexB_A = scrolledtext.ScrolledText(self.frmB,font=("consolas",10),width=132, height=16)
        self.separ = ttk.Separator(self.frmB, orient=HORIZONTAL, style='red.TSeparator')
        self.TexB_B = scrolledtext.ScrolledText(self.frmB,font=("consolas",10),width=132, height=16)

        self.TexB_A.grid(row=0,column=0,padx=2, pady=2,sticky=W)
        self.separ.grid(row=1, column=0, sticky='ew')
        self.TexB_B.grid(row=2,column=0,padx=2, pady=2,sticky=W)

        self.TexB_A.bind("<Button-3>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件

    def change_type(self,*args):
        java_type = Ent_yso_Top_type.get()
        if java_type == '-cp':
            self.comboxlist_A_class["values"] = tuple(Ysoserial_ter.ysoother_list)
        else:
            self.comboxlist_A_class["values"] = tuple(Ysoserial_ter.ysoclass_list)
        self.comboxlist_A_class.current(0)

    def change_class(self,*args):
        java_class = Ent_yso_Top_class.get()
        if java_class == 'ysoserial.Deserializer':
            Ent_yso_Top_cmd.set('提示: 请输入序列化后的文件名')
        else:
            Ent_yso_Top_cmd.set('whoami')
        

    def Exploit(self):
        java_type = Ent_yso_Top_type.get()
        java_class = Ent_yso_Top_class.get()
        java_cmd = Ent_yso_Top_cmd.get().strip('\n')
        
        #if java_cmd.startswith('aced'):
        #    java_cmd = binascii.a2b_hex(java_cmd)

        try:
            Ysoserial_ter.java_payload = ysoserial_payload(java_type=java_type,java_class=java_class,java_cmd=java_cmd)
            #delText(self.TexB_A)
            self.TexB_A.delete('1.0','end')
            self.TexB_A.insert(INSERT, binascii.hexlify(Ysoserial_ter.java_payload).decode())
            #self.TexB_A.configure(state="disabled")
        except Exception as e:
            Ysoserial_ter.java_payload = None
            messagebox.showinfo(title='错误!', message=str(e))

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        #menubar.add_command(label='a2b_hex',command=lambda:self.a2b_hex(self.TexB_A.get(1.0, "end").strip('\n')))
        menubar.add_command(label='b2a_base64',command=lambda:self.b2a_base64(self.TexB_A.get(1.0, "end").strip('\n')))
        menubar.add_command(label='save_file',command=self.save_file)
        #menubar.add_command(label='a2b_save_file',command=self.save_file)
        menubar.post(event.x_root,event.y_root)


    def a2b_hex(self, now_text):
        try:
            text = binascii.a2b_hex(now_text).decode()
            self.TexB_B.delete('1.0','end')
            self.TexB_B.insert(INSERT, text)
        except Exception as e:
            messagebox.showinfo(title='错误!', message=str(e))

    def b2a_base64(self, now_text):
        try:
            text = base64.b64encode(binascii.a2b_hex(now_text)).decode()  #加密
            self.TexB_B.delete('1.0','end')
            self.TexB_B.insert(INSERT, text)
        except Exception as e:
            messagebox.showinfo(title='错误!', message=str(e))

    def save_file(self):
        file_path = filedialog.asksaveasfilename(title=u'保存文件')
        if file_path:
            try:
                with open(file=file_path, mode='wb+') as file:
                    file.write(Ysoserial_ter.java_payload)
                messagebox.showinfo(title='提示', message='保存成功')
            except Exception as e:
                messagebox.showinfo(title='错误!', message=str(e))

class Data_debug():
    def __init__(self, root):
        self.Debug = Toplevel(root)
        self.Debug.title("TCP调试工具")
        self.Debug.geometry('700x450+650+150')
        self.Debug.protocol("WM_DELETE_WINDOW", self.callbackClose)
        self.exchange = self.Debug.resizable(width=False, height=False)#不允许扩大

        self.frmLeft = Frame(self.Debug, width=345, height=450, bg="whitesmoke")
        self.frmRight = Frame(self.Debug, width=345, height=450, bg="whitesmoke")
        self.frmLeft.grid(row=0, column=0, padx=2, pady=2)
        self.frmRight.grid(row=0, column=1, padx=2, pady=2)

        self.frmLeft.grid_propagate(0)
        self.frmRight.grid_propagate(0)
        
        self.LA = Frame(self.frmLeft, width=340, height=50, bg="whitesmoke")
        self.LB = Frame(self.frmLeft, width=340, height=300, bg="whitesmoke")
        self.LC = Frame(self.frmLeft, width=340, height=100, bg="whitesmoke")
        
        self.LA.grid_propagate(0)
        self.LB.grid_propagate(0)
        self.LC.grid_propagate(0)
        self.LA.grid(row=0, column=0, padx=2, pady=2)
        self.LB.grid(row=1, column=0, padx=2, pady=2)
        self.LC.grid(row=2, column=0, padx=2, pady=2)
        
        """
        :目的IP
        :端  口
        """
        self.LA_LabA = Label(self.LA, text='目的IP')#目的IP
        self.LA_EntA = Entry(self.LA, width='20',highlightcolor='red', highlightthickness=1,textvariable=TCP_Debug_IP,font=("consolas",10))#IP
        self.LA_LabB = Label(self.LA, text='端   口')#目的端口
        self.LA_EntB = Entry(self.LA, width='10',highlightcolor='red', highlightthickness=1,textvariable=TCP_Debug_PORT,font=("consolas",10))#PORT
        
        self.LA_LabA.grid(row=0, column=0, padx=2, pady=2, sticky=W)
        self.LA_EntA.grid(row=0, column=1, padx=2, pady=2, sticky=W)
        self.LA_LabB.grid(row=1, column=0, padx=2, pady=2, sticky=W)
        self.LA_EntB.grid(row=1, column=1, padx=2, pady=2, sticky=W)
        """
        """
        self.LB_top = Frame(self.LB, width=340, height=30, bg="whitesmoke")
        self.LB_bottom = Frame(self.LB, width=340, height=270, bg="whitesmoke")
        self.LB_top.grid_propagate(0)
        self.LB_bottom.grid_propagate(0)
        self.LB_top.grid(row=0, column=0, padx=2, pady=2)
        self.LB_bottom.grid(row=1, column=0, padx=2, pady=2)
        
        #self.LB_top_checkbutton_1 = Button(self.LB_top, text='connect', width=9, activebackground = "whitesmoke", command=lambda :self.thread_it(self.connect))
        self.LB_top_checkbutton_2 = Button(self.LB_top, text='send', width=9, activebackground = "whitesmoke", command=lambda :self.thread_it(self.send))
        self.LB_top_checkbutton_3 = Button(self.LB_top, text='close', width=9, activebackground = "whitesmoke", command=lambda :self.thread_it(self.close))
        
        #self.LB_top_checkbutton_1.grid(row=0, column=0, padx=2, pady=2)
        self.LB_top_checkbutton_2.grid(row=0, column=0, padx=2, pady=2)
        self.LB_top_checkbutton_3.grid(row=0, column=1, padx=2, pady=2)
        """
        """
        self.LB_bottom_TexA = scrolledtext.ScrolledText(self.LB_bottom,font=("consolas",10),width='45',height='17', undo = True)
        self.LB_bottom_TexA.grid(row=0, column=0, padx=2, pady=2)
        """
        """
        self.LC_TexC = scrolledtext.ScrolledText(self.LC,font=("consolas",10),width='45',height='5', undo = True)
        self.LC_TexC.grid(row=0, column=0, padx=2, pady=2)
        """
        """
        self.LD = Frame(self.frmRight, width=340, height=30, bg="whitesmoke")
        self.LE = Frame(self.frmRight, width=340, height=410, bg="whitesmoke")
        
        self.LD.grid_propagate(0)
        self.LE.grid_propagate(0)
        self.LD.grid(row=0, column=0, padx=2, pady=2)
        self.LE.grid(row=1, column=0, padx=2, pady=2)
        
        self.LD_LabA = Label(self.LD, text="接收缓冲区大小")
        self.LD_LabB = Label(self.LD, text="字节")
        self.LD_EntA = Entry(self.LD, width='10',highlightcolor='red', highlightthickness=1,textvariable=TCP_Debug_PKT_BUFF_SIZE,font=("consolas",10))#URL
        self.LD_LabA.grid(row=0, column=0, padx=2, pady=2, sticky=W)
        self.LD_LabB.grid(row=0, column=2, padx=2, pady=2, sticky=W)
        self.LD_EntA.grid(row=0, column=1, padx=2, pady=2, sticky=W)
        
        self.frmRight_TexC = scrolledtext.ScrolledText(self.LE,font=("consolas",10),width='45',height='27', undo = True)
        self.frmRight_TexC.bind("<Button-3>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件
        self.frmRight_TexC.grid(row=0, column=0, padx=2, pady=2)
        
        """
        输出重定向
        """
        sys.stdout = TextRedirector(self.LC_TexC, "stdout")
        sys.stderr = TextRedirector(self.LC_TexC, "stderr")
        
    def connect(self):
        remote_ip = TCP_Debug_IP.get()
        remote_port = TCP_Debug_PORT.get()
        
        self.remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote_conn.setblocking(True)
        try:
            self.remote_conn.settimeout(3)
            self.remote_conn.connect((remote_ip, remote_port))
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Establish connection success to %s %s'%(remote_ip, remote_port))
            self.recv_thread = threading.Thread(target=self.recv,daemon=True)
            self.recv_thread.start()
        except Exception as e:
            self.remote_conn.close()
            self.remote_conn = None
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Establish connection failed %s'%e)
        
    def close(self):
        try:
            _async_raise(self.recv_thread.ident, SystemExit)
            self.remote_conn.close()
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Closed socket success')
        except Exception as e:
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Failed Closing socket. %s'%e)

    def send(self):
        self.connect()
        if self.remote_conn:
            try:
                data_raw = self.LB_bottom_TexA.get('0.0','end').strip('\n')
                #output = binascii.unhexlify(data_raw)
                #data_send = output.decode("utf-8", "ignore")
                data_send = bytes.fromhex(data_raw)
                self.remote_conn.sendall(data_send)
                print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Send data %s bytes'%len(data_send))
            except Exception as e:
                print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Failed sending data. %s'%e)

    def recv(self):
        self.frmRight_TexC.delete('1.0','end')
        while True:
            try:
                #print(TCP_Debug_PKT_BUFF_SIZE.get())
                data_recv_raw = self.remote_conn.recv(TCP_Debug_PKT_BUFF_SIZE.get())
                if data_recv_raw:
                    print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Received data %s bytes'%len(data_recv_raw))
                    #print('[-] No more data is received.')
                    break
            except Exception as e:
                print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Failed recving data. %s'%e)
        data_recv = binascii.hexlify(data_recv_raw)
        self.frmRight_TexC.insert(INSERT, data_recv)
        self.close()
        return

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        #menubar.add_command(label='a2b_hex',command=lambda:self.a2b_hex(self.TexB_A.get(1.0, "end").strip('\n')))
        menubar.add_command(label='hex_to_str',command=lambda:self.hex_to_str(self.frmRight_TexC.get(1.0, "end").strip('\n')))
        #menubar.add_command(label='save_file',command=self.save_file)
        #menubar.add_command(label='a2b_save_file',command=self.save_file)
        menubar.post(event.x_root,event.y_root)

    def hex_to_str(self, hex_byte):
        try:
            a_byte = binascii.unhexlify(hex_byte) #unhexlify()传入的参数也可以是b'xxxx'(xxxx要符合16进制特征)
            text = a_byte.decode("utf-8", "ignore")
            self.frmRight_TexC.delete('1.0','end')
            self.frmRight_TexC.insert(INSERT, text)
        except Exception as e:
            messagebox.showinfo(title='错误!', message=str(e))

    #退出函数
    def callbackClose(self):
        sys.stdout = TextRedirector(gui.TexB, "stdout")
        sys.stderr = TextRedirector(gui.TexB, "stderr")
        #self.close()
        self.Debug.destroy()
    #多线程执行函数
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs,name='执行函数子线程',daemon=True)
        self.t.start()# 启动


class Proxy_pool():
    Proxy_list = []
    columns = ("proxy", "https", "anonymous")
    def __init__(self, root):

        self.Proxy = Toplevel(root)
        self.Proxy.title("免费代理")
        self.Proxy.geometry('400x450+650+150')
        self.exchange = self.Proxy.resizable(width=False, height=False)#不允许扩大
        #self.Proxy.wm_attributes('-topmost',1)

        self.frmA = Frame(self.Proxy, width=395, height=50, bg="whitesmoke")
        self.frmB = Frame(self.Proxy, width=395, height=370, bg="whitesmoke")
        self.frmC = Frame(self.Proxy, width=395, height=10, bg="whitesmoke")
        self.frmA.grid(row=0, column=0, padx=3, pady=3)
        self.frmB.grid(row=1, column=0, padx=3, pady=3)
        self.frmC.grid(row=2, column=0, padx=3, pady=3)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        self.frmC.grid_propagate(0)

        self.menubar = Menu(self.Proxy)

        self.menubar.add_command(label = "打开", command=lambda:LoadCMD('/Proxy'))
        self.menubar.add_command(label = "保存", command=self.save_tree)
        self.menubar.add_command(label = "清空", command=self.del_tree)
        self.menubar.add_command(label = "显示", command=self.show_proxy)
        self.menubar.add_command(label = "去重", command=self.remove_same)
        self.menubar.add_command(label = "重新载入", command=lambda :self.reload())
        self.menubar.add_command(label = "HTTP", command=lambda :self.select_tree(selPro='HTTP'))
        self.menubar.add_command(label = "HTTPS", command=lambda :self.select_tree(selPro='HTTPS'))
        #self.menubar.add_command(label="检查代理存活性", command=lambda :self.thread_it(self.checkProxy))

        self.Proxy.config(menu = self.menubar)

        self.LabA = Label(self.frmA, text='来源')#显示
        self.comboxlistA = ttk.Combobox(self.frmA,width=10,textvariable=variable_dict["Proxy_webtitle"],state='readonly') #接受输入控件
        #self.comboxlistA["values"]=("米扑代理","66代理","pzzqz","神鸡代理","快代理","极速代理","云代理","小幻代理","免费代理库","89免费代理","西拉代理")
        self.comboxlistA["values"]=("米扑代理","快代理","云代理","小幻代理","免费代理库","89免费代理","西拉代理")


        self.LabA1 = Label(self.frmA, text='页数')#显示
        self.comboxlistA1 = ttk.Combobox(self.frmA,width=3,textvariable=variable_dict["Proxy_page"],state='readonly') #接受输入控件
        self.comboxlistA1["values"]=("1","2","3","4","5","6","7","8","9","10")

        #self.comboxlistA2 = ttk.Combobox(self.frmA,width=3,textvariable=variable_dict["Proxy_page"],state='readonly') #接受输入控件
        #self.comboxlistA2["values"]=("1","2","3","4","5","6","7","8","9","10")

        #获取代理功能按钮
        self.buttonA = Button(self.frmA, text="获取", width=24, height=2, command=lambda :self.thread_it(self.get_proxy))

        self.VScroll1 = Scrollbar(self.frmB, orient='vertical')
        self.tree = ttk.Treeview(self.frmB, height=20, columns=Proxy_pool.columns, show="headings",yscrollcommand=self.VScroll1.set)
        self.VScroll1['command'] = self.tree.yview
    
        #self.tree.bind("<ButtonRelease-1>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, gui.menubar_1))#绑定右键鼠标事件
        self.tree.heading("proxy", text="IP地址", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'proxy', False))
        self.tree.heading("https", text="类型", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'https', False))
        self.tree.heading("anonymous", text="匿名度", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'anonymous', False))
        # 定义各列列宽及对齐方式
        self.tree.column("proxy", width=170, anchor="w")
        self.tree.column("https", width=100, anchor="center")
        self.tree.column("anonymous", width=100, anchor="center")


        self.p1 = ttk.Progressbar(self.frmC, length=395, mode="determinate",maximum=395,orient=HORIZONTAL)
        self.p1.grid(row=0,column=0,sticky=W)
        #布局方式
        self.LabA.grid(row=0, column=0,padx=2, pady=2)
        self.comboxlistA.grid(row=0, column=1,padx=2, pady=2)
        self.LabA1.grid(row=0, column=2,padx=2, pady=2)
        self.comboxlistA1.grid(row=0, column=3,padx=2, pady=2)
        self.buttonA.grid(row=0, column=4,padx=3, pady=3)

        self.tree.grid(row=0,column=0,padx=1, pady=1)#grid方案
        self.VScroll1.grid(row=0,column=1,padx=1, pady=1,sticky='ns')

        #初始化
        self.init_proxylist()

    #去重
    def remove_same(self):
        temp_list = []
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[0]
            if item_text in temp_list:
                self.tree.delete(item)
            else:
                temp_list.append(item_text)
    #筛选
    def select_tree(self, selPro=''):
        selPro = True if selPro == 'HTTPS' else False
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[1]
            if selPro and 'HTTPS' in item_text:
                pass
            elif selPro and 'HTTPS' not in item_text:
                #删除HTTP节点
                self.tree.delete(item)
            elif 'HTTPS' == item_text:
                #删除HTTPS节点
                self.tree.delete(item)

    #导入1
    def init_proxylist(self):
        with open('./Proxy/ips.txt', mode='r', encoding='utf-8') as f:
            for line in f.readlines():
                try:
                    _dict = json.loads(line.strip('\n'))
                    Proxy_pool.Proxy_list.append(_dict.get("proxy", ""))
                    self.tree.insert("","end",values=(
                                _dict.get("proxy", ""),
                                _dict.get("https", ""),
                                _dict.get("anonymous", "")
                                )
                            )
                except Exception:
                    continue

    #获取代理1
    def get_proxy(self):
        try:
            p = ProxyFetcher()
            result = getattr(p, Proxy_web[variable_dict["Proxy_webtitle"].get()])(variable_dict["Proxy_page"].get())

            for i in [_.split("|") for _ in result]:
                self.tree.insert("","end",values=(i[0], i[1], i[2]))
                Proxy_pool.Proxy_list.append(i[0])
        except Exception as e:
            print(e)
    #输出代理1
    def show_proxy(self):
        temp = self.get_tree()
        for i in temp:
            print(i.get("proxy", ""))

    #清空所有1
    def del_tree(self):
        x = self.tree.get_children()
        for item in x:
            self.tree.delete(item)

    def reload(self):
        self.del_select()
        self.init_proxylist()

    #删除选中的行1
    def del_select(self):
        for selected_item in self.tree.selection():
            self.tree.delete(selected_item)

    #复制选中行到剪切板中1
    def copy_select(self):
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                proxy = item_text[0]#输出所选行的第一列的值
            addToClipboard(proxy)
            #命令执行方式会闪屏
            #command = 'echo | set /p nul=' + text.strip() + '| clip'
            #os.system(command)
        except Exception as e:
            pass

    #保存当前数据1
    def save_tree(self):
        with open('./Proxy/ips.txt', mode='w', encoding='utf-8') as f:
            f.writelines([json.dumps(i)+'\n' for i in self.get_tree()])
            f.close()

    #获取当前数据1
    def get_tree(self):
        temp_list = []
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")
            str_to_dict = '{"proxy":"%s", "https":"%s", "anonymous":"%s"}'%(item_text[0], item_text[1], item_text[2])
            temp_list.append(json.loads(str_to_dict))
        return temp_list

    #排序函数
    def treeview_sort_column(self, tv, col, reverse):#Treeview、列名、排列方式
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        #print(tv.get_children(''))
        l.sort(reverse=reverse)#排序方式
        # rearrange items in sorted positions
        for index, (val, k) in enumerate(l):#根据排序后索引移动
            tv.move(k, '', index)
            #print(k)
        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))#重写标题，使之成为再点倒序的标题


    #检查代理存活性
    def checkProxy(self, anonymous):
        temp_list = self.get_tree()
        Proxy_pool.Proxy_list.clear()
        result_list = []
        self.p1["value"] = 0
        try:
            start = time.time()
            flag = round(395/len(temp_list), 2)#每执行一个任务增长的长度
            index = [Proxy_cls(**kwargs) for kwargs in temp_list]
            executor = ThreadPoolExecutor(max_workers = 10)
            for data in executor.map(DoValidator.http_or_https, index, repeat(anonymous)):
                result_list.append(data)#汇聚结果
                self.p1["value"] = self.p1["value"] + flag#进度条
                gui.root.update()
    
            self.del_tree()
            for proxy in index:
                if proxy.last_status is not None:
                    Proxy_pool.Proxy_list.append(proxy.proxy)
                    self.tree.insert("","end",values=(proxy.proxy, proxy.https, proxy.anonymous))
            end = time.time()
            print('[*]检查完成!\n[*]当前存活IP: %s 个\n[*]共花费时间: %s 秒'%(len(Proxy_pool.Proxy_list),seconds2hms(end - start)))
            #messagebox.showinfo(title='提示', message='检查完成!\n[*]当前存活IP: %s 个\n[*]共花费时间: %s 秒'%(len(Proxy_pool.Proxy_list),seconds2hms(end - start)))
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*]检查完成!\n[*]当前存活IP: %s 个\n[*]共花费时间: %s 秒"%(len(Proxy_pool.Proxy_list),seconds2hms(end - start)))

        except Exception as e:
            print('[-]检查代理存活性错误: %s'%e)
            #messagebox.showinfo(title='错误', message='错误: %s'%e)
            self.p1["value"] = 395
            gui.root.update()

    ##右键鼠标事件
    def treeviewClick(self, event, menubar):
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                proxy = item_text[0]
                #pro = 'HTTPS' if 'HTTPS' in item_text[1] else 'HTTP'
            ip = proxy.split(':')[0]
            port = proxy.split(':')[1]

            menubar.delete(0,END)
            menubar.add_command(label='复制',command=self.copy_select)
            menubar.add_command(label='删除',command=self.del_select)
            menubar.add_command(label='设置为当前代理', command=lambda:self.set_proxy(ip,port))
            menubar.add_command(label='检测普通代理存活性', command=lambda :self.thread_it(self.checkProxy, anonymous=False))
            menubar.add_command(label='检测高匿代理存活性', command=lambda :self.thread_it(self.checkProxy, anonymous=True))
            #menubar.add_command(label='检测HTTP代理存活', command=lambda:self.set_proxy(ip,port,pro))
            #menubar.add_command(label='检测HTTPS代理存活', command=lambda:self.set_proxy(ip,port,pro))
            #menubar.add_command(label='开启全局代理连接池', command=lambda :self.thread_it(self.start_proxy))

            menubar.post(event.x_root,event.y_root)
        except Exception as e:
            pass
            #messagebox.showinfo(title='提示', message=e)

    #设置代理
    def set_proxy(self, ip, port, pro='HTTP'):
        try:
            #代理初始化清空
            socks.set_default_proxy(None)
            socket.socket = socks.socksocket
            os.environ['HTTP_PROXY'] = ''
            os.environ['HTTPS_PROXY'] = ''
            #自定义值
            variable_dict["Proxy_CheckVar1"].set(1)
            variable_dict["Proxy_CheckVar2"].set(0)
            variable_dict["PROXY_TYPE"].set(pro)
            variable_dict["Proxy_addr"].set(ip)
            variable_dict["Proxy_port"].set(port)
            #代理全局
            os.environ['HTTP_PROXY'] = ip+':'+port
            os.environ['HTTPS_PROXY'] = ip+':'+port
            print('[*]设置代理成功\n[*]当前代理协议: %s\n[*]当前代理的IP: %s:%s'%(pro,ip,port))
            #now = datetime.datetime.now()
            #print("["+str(now)[11:19]+"] " + "[*]设置代理成功\n[*]当前代理协议: %s\n[*]当前代理的IP: %s:%s"%(pro,ip,port))
            #messagebox.showinfo(title='提示', message='设置代理成功\n[*]当前代理协议: %s\n[*]当前代理的IP: %s:%s'%(pro,ip,port))
        except Exception as e:
            print('[-]设置代理错误: %s'%e)
            #messagebox.showinfo(title='提示', message=e)

    #多线程执行函数
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs,name='执行函数子线程',daemon=True)
        self.t.start()# 启动

class terminal_infos:
    version='1.0'#版本
    by='Takanawa-door'#作者
    running_space={'__name__':'__console__'}#运行空间(用于存储变量的)
    exec('''def print(*value):
    return None
def input(*value):
    return None
def set(*value):
    return None
def Back(*value):
    pass
del input,print,set,Back''',running_space)#先把那些Python基础函数替换了
    input_list=[]#这个是输入命令记载输入命令的列表
    pos = None
    def __init__(self,root):
        Ent_B_Top_funtype.set('True')
        Ent_B_Bottom_Left_cmd.set('whoami')
        self.Terminal = Toplevel(root)
        #新建Text控件
        self.title = self.Terminal.title('命令执行终端')#设置title
        self.TerminalText = scrolledtext.ScrolledText(self.Terminal,width=110,height=25,state='d',fg='white',bg='black',insertbackground='white',font=('consolas',13),selectforeground='black',selectbackground='white',takefocus=False)
        self.TerminalText.pack(fill='both',expand='yes')

        #实现不同颜色的效果，用于insert插入标记
        self.TerminalText.tag_config('red',foreground='red',selectforeground='#00ffff',selectbackground='#ffffff')
        self.TerminalText.tag_config('green',foreground='green',selectforeground='#ff7eff',selectbackground='#ffffff')
        self.TerminalText.tag_config('blue',foreground='blue',selectforeground='#ffff7e',selectbackground='#ffffff')
        self.TerminalText.tag_config('cyan',foreground='cyan',selectforeground='red',selectbackground='#ffffff')

        self.TerminalText['state']='n'
        self.TerminalText.insert('end',f'EasyTerminal {terminal_infos.version} By {terminal_infos.by}\n')

        #后面的'green'就是tag标记，他会应用green这个tag的属性
        self.TerminalText.insert('end',f'{os.getcwd()}\n','green')
        self.TerminalText.insert('end',f'$ ')

        #命令输入框
        self.command_input = Entry(self.TerminalText,font=('consolas',13),textvariable=Ent_B_Bottom_terminal_cmd,fg='white',bg='black',insertbackground='white',selectforeground='black',selectbackground='white',relief='flat',width=80)
        self.command_input.bind('<Key-Return>',lambda v=0:self.run_command(self.command_input.get(),self.TerminalText,self.command_input))
        self.command_input.bind('<Key-Up>', lambda v=0:self.CmdbackUp(Ent_B_Bottom_terminal_cmd))
        self.command_input.bind('<Key-Down>', lambda v=0:self.CmdbackDown(Ent_B_Bottom_terminal_cmd))
        #在命令输入框中按F7弹出命令列表窗口
        #self.command_input.bind('<F7>',lambda v=0:self.post_inputlist(self.command_input))
        self.TerminalText.bind('<Key-Return>',lambda v=0:self.contiune_command())
        #插入命令输入框
        self.TerminalText.window_create('end',window=self.command_input)

        #让终端Text不可编辑
        #self.TerminalText['state']='d'

        sys.stdout = TextRedirector(self.TerminalText, "stdout", index="2")
        sys.stderr = TextRedirector(self.TerminalText, "stderr", index="2")

        self.Terminal.protocol("WM_DELETE_WINDOW", self.callbackClose)

    def CmdbackUp(self, entry_cmd_text):
        try:
            if terminal_infos.pos is None:
                pos = len(terminal_infos.input_list) - 1
            elif terminal_infos.pos == 0:
                return
            else:
                pos = terminal_infos.pos
            pos -= 1
            entry_cmd_text.set(terminal_infos.input_list[pos])
            terminal_infos.pos = pos#记录位置
            #self.command_input.xview_moveto(1)
        except IndexError:
            pass
        except Exception as e:
            print(e)

    def CmdbackDown(self, entry_cmd_text):
        try:
            if terminal_infos.pos is None:
                return
            elif terminal_infos.pos == len(terminal_infos.input_list)-1:
                return
            else:
                pos = terminal_infos.pos
            pos += 1
            entry_cmd_text.set(terminal_infos.input_list[pos])
            terminal_infos.pos = pos#记录位置
            #self.command_input.xview_moveto(1)
        except IndexError:
            pass
        except Exception as e:
            print(e)
    #运行输入的内容调用的函数
    def run_command(self,command,terminal,commandinput):
        if command == '':
            self.contiune_command()
            return
        errortext=f'错误指令"{command.strip()}"。'

        command=str(command)#这玩意是应付编辑器不知道command是什么类型的
        terminal_infos.input_list.append(command)#增加输入了什么命令
        terminal.config(state='n')#解锁terminal(Text)

        terminal.delete('end')#删除输入控件
        commandinput.delete(0,'end')#删除控件里输入的文本

        self.thread_it(self.exeCMD,**{
            'url':Ent_B_Top_url.get(),
            'cookie':Ent_B_Top_cookie.get(),
            'cmd':terminal_infos.input_list[-1],
            'pocname':Ent_B_Top_vulmethod.get(),
            'vuln':Ent_B_Top_funtype.get(),
            'timeout':Ent_B_Top_timeout.get(),
            'retry_time':Ent_B_Top_retry_time.get(),
            'retry_interval':Ent_B_Top_retry_interval.get()
            }
        )

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动

    #漏洞利用界面执行命令函数
    def exeCMD(self,**kwargs):
        print(self.command_input.get())
        if kwargs['url'] == '' or kwargs['cmd'] == '':
            #color('[*]请输入目标URL和命令','pink')
            return
        #start = time.time()
        try:
            print(kwargs['cmd'])
            MyEXP.vuln.check(**kwargs)
        except Exception as e:
            print('出现错误: %s'%e)
        #end = time.time()
        #print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
        self.contiune_command()

    def contiune_command(self):
        self.TerminalText.config(state='n')#解锁terminal(Text)
        self.TerminalText.insert('end',f'\n{os.getcwd()}\n','green')
        self.TerminalText.insert('end',f'$ ')
        self.TerminalText.window_create('end',window=self.command_input)
        self.command_input.focus_set()#"""
        self.TerminalText.config(state='d')
        self.TerminalText.see('end')

    #退出时执行的函数
    def callbackClose(self):
        try:
            sys.stdout = TextRedirector(exp.TexBOT_1_2, "stdout", index="2")
            sys.stderr = TextRedirector(exp.TexBOT_1_2, "stderr", index="2")
            self.Terminal.destroy()
        except Exception as e:
            self.Terminal.destroy()
        finally:
            Ent_B_Top_funtype.set('False')
            Ent_B_Bottom_Left_cmd.set('echo VuLnEcHoPoCSuCCeSS')



class terminal_cmds():
    cmds_list = ['反弹shell','获取WebShell','清理痕迹']
    def __init__(self,root):
        self.cmds = Toplevel(root)
        self.cmds.title("命令控制台")
        self.cmds.geometry('810x460+650+150')
        self.exchange = self.cmds.resizable(width=False, height=False)#不允许扩大

        #显示菜单
        self.frmA = Frame(self.cmds, width=300, height=455,bg="black")
        self.frmB = Frame(self.cmds, width=500, height=455,bg="red")
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=0, column=1, padx=2, pady=2)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)

        #下拉框
        self.comboxlist_A_com = ttk.Combobox(self.frmA,width='15',textvariable=Ent_Cmds_Top_type,state='readonly',font=("consolas",10))
        self.comboxlist_A_com["values"] = tuple(terminal_cmds.cmds_list)
        self.comboxlist_A_com.bind("<<ComboboxSelected>>", self.bind_combobox)
        self.comboxlist_A_com.grid(row=0,column=0,padx=1, pady=1,sticky=W)

        #
        self.Listbox_A_box = Listbox(self.frmA,selectmode=SINGLE,listvariable=Ent_Cmds_Top_typevar,width=41,height=26,borderwidth=2,font=("consolas",10))#height=26设置listbox组件的高度，默认是10行。
        self.Listbox_A_box.grid(row=1,columnspan=2,padx=1, pady=1,sticky=W)
        #self.TexA = scrolledtext.ScrolledText(self.frmA,font=("consolas",10),width='68',height='19', undo = True)
        #self.TexA.pack(side=LEFT,expand=YES,fill=BOTH)

        #self.TexA.insert(INSERT, now_text.replace(' ',''))
        #self.file.wm_attributes('-topmost',1)
        #self.file.protocol("WM_DELETE_WINDOW", self.close)

    def bind_combobox(self,*args):
        pass

#加载多目标类
class Loadfile():
    def __init__(self,root):
        self.file = Toplevel(root)
        self.file.title("文本选择")
        #self.file.rowconfigure(1, weight=1)
        #self.file.columnconfigure(0, weight=1)
        self.file.geometry('500x300+650+150')
        #self.exchange = self.file.resizable(width=False, height=False)#不允许扩大

        #顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "导 入", command=self.openfile)
        self.menubar.add_command(label = "清 空", command=self.clearfile)
        self.menubar.add_command(label = "添加http", command=self.addhttp)
        self.menubar.add_command(label = "添加https", command=self.addhttps)
        self.menubar.add_command(label = "base64解码", command=self.de_base64)
        self.menubar.add_command(label = "空字符分隔", command=self.split_null)
        self.menubar.add_command(label = "长字符格式化", command=self.long_Beautify)

        #显示菜单
        self.file.config(menu = self.menubar)
        self.frmA = Frame(self.file, width=795, height=395,bg="white")
        self.frmA.rowconfigure(0,weight=1)
        self.frmA.columnconfigure(0,weight=1)
        self.frmA.grid(row=0, column=0, padx=3, pady=3)

        self.TexA = scrolledtext.ScrolledText(self.frmA,font=("consolas",10),width='68',height='19', undo = True)
        self.TexA.pack(side=LEFT,expand=YES,fill=BOTH)

        self.TexA.insert(INSERT, MyGUI.now_text.replace(' ',''))
        #self.file.wm_attributes('-topmost',1)
        self.file.protocol("WM_DELETE_WINDOW", self.close)


    def openfile(self):
        default_dir = r"./"
        file_path = askopenfilename(title=u'选择文件', initialdir=(os.path.expanduser(default_dir)))
        try:
            with open(file_path, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                self.clearfile()
                for i in array: #遍历array中的每个元素
                    self.TexA.insert(INSERT, i.replace(' ',''))
        except Exception as e:
            pass
        

    def clearfile(self):
        MyGUI.now_text = ''
        self.TexA.delete('1.0','end')

    def close(self):
        MyGUI.now_text = self.TexA.get('0.0','end')
        self.file.destroy()

    def addhttp(self):
        MyGUI.now_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = MyGUI.now_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            #i = '192.168.'+i.replace('http://','').replace('https://','')
            i = 'http://'+i.replace('http://','').replace('https://','')
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1
        MyGUI.now_text = self.TexA.get('0.0','end')

    def addhttps(self):
        MyGUI.now_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = MyGUI.now_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            i = 'https://'+i.replace('http://','').replace('https://','')
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1
        MyGUI.now_text = self.TexA.get('0.0','end')

    def de_base64(self):
        MyGUI.now_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = MyGUI.now_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            try:
                result = base64.b64decode(i).decode()
            except Exception as e:
                result = '[-]解密失败: '+ i
            finally:
                if index == len(array):
                    self.TexA.insert(INSERT, result)
                else:
                    self.TexA.insert(INSERT, result+'\n')
                index = index+1
        MyGUI.now_text = self.TexA.get('0.0','end')

    def split_null(self):
        MyGUI.now_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = MyGUI.now_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            try:
                result = i.split()[0]
            except Exception as e:
                pass
            finally:
                if index == len(array):
                    self.TexA.insert(INSERT, result)
                else:
                    self.TexA.insert(INSERT, result+'\n')
                index = index+1
        MyGUI.now_text = self.TexA.get('0.0','end')

    def long_Beautify(self, index=70, prefix="r\"", suffix="\" \\"):
        MyGUI.now_text = self.TexA.get('0.0','end').strip('\n')
        self.TexA.delete('1.0','end')
        
        short_str = ""
        for _str in wrap(MyGUI.now_text, width=index):
            short_str += prefix + _str + suffix + "\n"
            
        self.TexA.insert(INSERT, short_str)
        MyGUI.now_text = self.TexA.get('0.0','end')

#编辑代码界面类
class Topfile():
    def __init__(self,root,file_name,Logo,vuln_select):
        if Logo == '2':
            self.file_name1 = './EXP/' + file_name + '.py'
        else:
            self.file_name1 = './POC/' + file_name + '.py'
        #print(self.file_name1)
        if os.path.exists(self.file_name1) == False:
            messagebox.showinfo(title='提示', message='还未选择模块')
            #print('[-]还未选择模块,无法编辑')
            return
        self.vuln_select = vuln_select
        self.file_name = file_name
        self.file = Toplevel(root)
        self.file.title("文本编辑")
        self.file.geometry('800x400+650+150')
        self.exchange = self.file.resizable(width=False, height=False)#不允许扩大
        #顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "保 存", accelerator="ctrl + s", command=lambda :self.save_file('1',self.vuln_select))
        self.menubar.add_command(label = "撤 销", accelerator="Ctrl + Z", command=self.move)
        self.file.bind("<Control-s>",lambda event:self.save_file('1',self.vuln_select))

        #显示菜单
        self.file.config(menu = self.menubar)

        self.frmA = Frame(self.file, width=795, height=395,bg="white")
        self.frmA.grid(row=0, column=0, padx=3, pady=3)

        self.TexA = scrolledtext.ScrolledText(self.frmA,font=("consolas",10),width='110',height='25',undo = True)
        self.TexA.pack(side=LEFT,expand=YES,fill=BOTH)
        self.TexA.bind('<KeyRelease>', self.process_key)

        self.TexA.tag_config('bif', foreground='purple')
        self.TexA.tag_config('kw', foreground='orange')
        self.TexA.tag_config('comment', foreground='red')
        self.TexA.tag_config('string', foreground='green')

        self.openRender()
    def move(self):
        self.TexA.edit_undo()

    def openRender(self):
        try:
            with open(self.file_name1, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                for i in array: #遍历array中的每个元素
                    self.TexA.insert(INSERT, i)
        except FileNotFoundError:
            print('[-]还未选择模块,无法编辑')
            return

    def save_file(self,event,vuln_select):
        #if messagebox.askokcancel('提示','要执行此操作吗?') == True:
        if vuln_select == None:
            self.file.destroy()
            messagebox.showinfo(title='提示', message='还未选择模块')
            return
        save_data = str(self.TexA.get('0.0','end'))
        try:
            fobj_w = open(self.file_name1, 'w',encoding='utf-8')
            fobj_w.writelines(save_data)
            fobj_w.close()
            #self.openRender()
            vuln_select = importlib.reload(vuln_select)
            #vuln = importlib.import_module('.%s'%self.file_name,package='EXP')
            #messagebox.showinfo(title='结果', message='保存成功')
            print('[*]保存成功,%s模块已重新载入!'%self.file_name)
        except Exception as e:
            print("异常对象的内容是%s"%e)
            #print(self.file_name1)
            messagebox.showerror(title='结果', message='出现错误')
        
    def process_key(self,key):
        current_line_num, current_col_num = map(int, self.TexA.index(INSERT).split('.'))
        if key.keycode == 13:
            last_line_num = current_line_num - 1
            last_line = self.TexA.get(f'{last_line_num}.0', INSERT).rstrip()
            #计算最后一行的前导空格数量
            num = len(last_line) - len(last_line.lstrip(' '))
            #最后一行以冒号结束，或者冒号后面有#单行注释
            if (last_line.endswith(':') or
                (':' in last_line and last_line.split(':')[-1].strip().startswith('#'))):
                num = num + 4
            elif last_line.strip().startswith(('return','break','continue','pass','raise')):
                num = num - 4
            self.TexA.insert(INSERT,' '*num)
        #按下退格键BackSpace
        
        elif key.keysym == 'BackSpace':
            #当前行从开始到鼠标位置的内容
            current_line = self.TexA.get(f'{current_line_num}.0',f'{current_line_num}.{current_col_num}')
            #当前光标位置前面的空格数量
            num = len(current_line) - len(current_line.rstrip(' '))
            #最多删除4个空格
            #这段代码是按下退格键删除了一个字符之后才执行的，所以还需要再删除最多3个空格
            num = min(4,num)
            if num > 1 and num != 4:
                self.TexA.delete(f'{current_line_num}.{current_col_num-num}',f'{current_line_num}.{current_col_num}')

#漏洞利用界面类
class MyEXP:
    exp_scripts = ['ALL']#EXP下的脚本列表
    exp_scripts_cve = ['ALL']#EXP下的脚本下的CVE编号
    vuln = None
    #output = ''
    def __init__(self,root,frmEXP):
        self.frmEXP = frmEXP
        self.root = root

    def CreateFrm(self):
        self.frmTOP = Frame(self.frmEXP, width=960, height=180,bg='white')
        self.frmBOT = Frame(self.frmEXP, width=960, height=430,bg='white')

        self.frmTOP.grid(row=0, column=0, padx=2, pady=2)
        self.frmBOT.grid(row=1, column=0, padx=2, pady=2)
        self.frmTOP.grid_propagate(0)
        self.frmBOT.grid_propagate(0)

        self.frmA = Frame(self.frmTOP, width=560, height=180,bg='white')#目标，输入框
        self.frmB = Frame(self.frmTOP, width=400, height=180, bg='white')#输出信息
        #self.frmC = Frame(self.frmTOP, width=960, height=380, bg='black')#输出信息
        
        #表格布局
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=0, column=1, padx=2, pady=2)
        #self.frmC.grid(row=1, column=0, padx=2, pady=2)

        #固定大小
        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        #self.frmC.grid_propagate(0)

    def CreateFirst(self):
        self.frame_1 = LabelFrame(self.frmA, text="基本配置", labelanchor="nw", width=550, height=90, bg='white')
        self.frame_2 = LabelFrame(self.frmA, text="参数配置", labelanchor="nw", width=550, height=83, bg='white')
        #self.frame_3 = LabelFrame(self.frmA, text="heads", labelanchor="nw", width=360, height=250, bg='black')
        self.frame_1.grid(row=0, column=0, padx=2, pady=2)
        self.frame_2.grid(row=1, column=0, padx=2, pady=2)
        #self.frame_3.grid(row=0, column=1, padx=2, pady=2)
        self.frame_1.grid_propagate(0)
        self.frame_2.grid_propagate(0)
        #self.frame_3.grid_propagate(0)

        ###基本配置
        self.label_1 = Label(self.frame_1, text="目标地址")
        self.EntA_1 = Entry(self.frame_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=Ent_B_Top_url,font=("consolas",10)) #接受输入控件

        self.Button_1 = Button(self.frame_1, text='......', width=6, command=lambda :Loadfile(self.root)) #批量导入文件

        #self.label_2 = Label(self.frame_1, text="Cookie")
        #self.EntA_2 = Entry(self.frame_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=Ent_B_Top_cookie,font=("consolas",10)) #接受输入控件

        self.label_3 = Label(self.frame_1, text="漏洞名称")
        self.comboxlist_3 = ttk.Combobox(self.frame_1,width='20',textvariable=Ent_B_Top_vulname,state='readonly') #接受输入控件
        self.comboxlist_3["values"] = tuple(MyEXP.exp_scripts)
        self.comboxlist_3.bind("<<ComboboxSelected>>", bind_combobox)

        self.comboxlist_3_1 = ttk.Combobox(self.frame_1,width='32',textvariable=Ent_B_Top_vulmethod,state='readonly') #接受输入控件2
        self.button_3 = Button(self.frame_1, text="编辑文件", width=6, command=lambda:Topfile(gui.root,Ent_B_Top_vulname.get(),'2',MyEXP.vuln))

        
        self.label_1.grid(row=0,column=0,padx=1, pady=1)
        self.EntA_1.grid(row=0,columnspan=4,padx=1, pady=1)
        self.Button_1.grid(row=0,column=3,padx=1, pady=1)

        #self.label_2.grid(row=1,column=0,padx=1, pady=1)
        #self.EntA_2.grid(row=1,columnspan=4,padx=1, pady=1)

        self.label_3.grid(row=2,column=0,padx=1, pady=1,sticky=W)
        self.comboxlist_3.grid(row=2,column=1,padx=1, pady=1,sticky=W)
        self.comboxlist_3_1.grid(row=2,column=2,padx=1, pady=1,sticky=W)
        self.button_3.grid(row=2,column=3,padx=1, pady=1,sticky=W)

        
        self.label_4 = Label(self.frame_2, text="命令执行(True/False)")
        self.comboxlist_4 = ttk.Combobox(self.frame_2,width='8',textvariable=Ent_B_Top_funtype,state='readonly') #接受输入控件
        self.comboxlist_4["values"] = tuple(['True','False'])
        self.comboxlist_4.bind("<<ComboboxSelected>>", bind_combobox_3)

        self.label_5 = Label(self.frame_2, text="超时时间(Timeout)")
        self.b5 = Spinbox(self.frame_2,from_=1,to=10,wrap=True,width=3,font=("consolas",10),textvariable=Ent_B_Top_timeout)

        self.label_6 = Label(self.frame_2, text="重试次数(retry_time)")
        self.b6 = Spinbox(self.frame_2,from_=1,to=10,wrap=True,width=3,font=("consolas",10),textvariable=Ent_B_Top_retry_time)

        self.label_7 = Label(self.frame_2, text="重试间隔(retry_interval)")
        self.b7 = Spinbox(self.frame_2,from_=1,to=10,wrap=True,width=3,font=("consolas",10),textvariable=Ent_B_Top_retry_interval)

        self.label_4.grid(row=0,column=0,padx=3, pady=3, sticky=W)
        self.comboxlist_4.grid(row=0,column=1,padx=3, pady=3, sticky=W)

        self.label_5.grid(row=0,column=2,padx=3, pady=3, sticky=W)
        self.b5.grid(row=0,column=3,padx=3, pady=3, sticky=W)

        self.label_6.grid(row=1,column=0,padx=3, pady=3, sticky=W)
        self.b6.grid(row=1,column=1,padx=3, pady=3, sticky=W)      

        self.label_7.grid(row=1,column=2,padx=3, pady=3, sticky=W)
        self.b7.grid(row=1,column=3,padx=3, pady=3, sticky=W)

    def CreateSecond(self):
        self.frame_B1 = LabelFrame(self.frmB, text="备注", labelanchor="nw", width=400, height=180, bg='white')
        self.frame_B1.grid(row=0, column=0, padx=2, pady=2)
        self.frame_B1.propagate()

        self.TexB1 = Text(self.frame_B1, font=("consolas",10), width=50, height=10)
        self.ScrB1 = Scrollbar(self.frame_B1)

        self.TexB1.grid(row=0, column=0, padx=1, pady=1)
        self.ScrB1.grid(row=0, column=1, sticky=S + W + E + N)
        self.ScrB1.config(command=self.TexB1.yview)
        self.TexB1.config(yscrollcommand=self.ScrB1.set)

        with open('./lib/note.txt', mode='r', encoding='utf-8') as f:
            array = f.readlines()
            for i in array: #遍历array中的每个元素
                self.TexB1.insert(INSERT, i)

    def CreateThird(self):
        self.frmBOT_1 = LabelFrame(self.frmBOT, text="命令执行", labelanchor="nw", width=950, height=430, bg='white')
        self.frmBOT_1_1 = Frame(self.frmBOT_1,width=940, height=30,bg='white')
        self.frmBOT_1_2 = Frame(self.frmBOT_1,width=940, height=400,bg='white')

        self.frmBOT_1.grid(row=0, column=0 , padx=2, pady=2)
        self.frmBOT_1_1.grid(row=0, column=0 , padx=2, pady=2)
        self.frmBOT_1_2.grid(row=1, column=0 , padx=2, pady=2)

        self.frmBOT_1.propagate()
        self.frmBOT_1_1.propagate()
        self.frmBOT_1_2.propagate()

        self.labelBOT_1 = Label(self.frmBOT_1_1, text="CMD命令")
        self.EntABOT_1 = Entry(self.frmBOT_1_1, width='100',highlightcolor='red', highlightthickness=1,textvariable=Ent_B_Bottom_Left_cmd,font=("consolas",10)) #接受输入控件
        self.EntABOT_1.insert(0, "echo VuLnEcHoPoCSuCCeSS")
        self.buttonBOT_1 = Button(self.frmBOT_1_1, text="执行命令",command=lambda :self.thread_it(exeCMD,**{
            'url' : Ent_B_Top_url.get(),
            'cookie' : Ent_B_Top_cookie.get(),
            'cmd' : Ent_B_Bottom_Left_cmd.get(),
            'pocname' : Ent_B_Top_vulmethod.get(),
            'vuln' : Ent_B_Top_funtype.get(),
            'timeout' : Ent_B_Top_timeout.get(),
            'retry_time' : Ent_B_Top_retry_time.get(),
            'retry_interval' : Ent_B_Top_retry_interval.get()
            }
        ))
        self.buttonBOT_2 = Button(self.frmBOT_1_1, text='清空信息', command=lambda :delText(exp.TexBOT_1_2))

        self.ColorImage = PhotoImage(file="./lib/red.png")
        self.ColorButton = Button(self.frmBOT_1_1, image=self.ColorImage)
        self.ColorButton["bg"] = "white"
        self.ColorButton["border"] = "0"

        self.labelBOT_1.grid(row=0, column=0 , padx=2, pady=2,sticky=W)
        self.EntABOT_1.grid(row=0, column=1 , padx=2, pady=2,sticky=W)
        self.buttonBOT_1.grid(row=0, column=2 , padx=2, pady=2,sticky=W)
        self.buttonBOT_2.grid(row=0, column=3 , padx=2, pady=2,sticky=W)
        self.ColorButton.grid(row=0, column=4 , padx=2, pady=2,sticky=W)

        self.TexBOT_1_2 = Text(self.frmBOT_1_2, font=("consolas",10), width=132, height=23,bg='black')
        self.ScrBOT_1_2 = Scrollbar(self.frmBOT_1_2)  #滚动条控件

        self.TexBOT_1_2.bind("<Button-3>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件
        #提前定义颜色
        self.TexBOT_1_2.tag_add("here", "1.0","end")
        self.TexBOT_1_2.tag_config("here", background="black")

        self.TexBOT_1_2.grid(row=0, column=1 , padx=2, pady=2)
        self.ScrBOT_1_2.grid(row=0, column=2, sticky=S + W + E + N)
        self.ScrBOT_1_2.config(command=self.TexBOT_1_2.yview)
        self.TexBOT_1_2.config(yscrollcommand=self.ScrBOT_1_2.set)

    def color_switch(self, color):
        self.ColorButton.grid_forget()
        self.ColorImage = PhotoImage(file="./lib/"+color+".png")
        self.ColorButton = Button(self.frmBOT_1_1, image=self.ColorImage)
        self.ColorButton["bg"] = "white"
        self.ColorButton["border"] = "0"
        self.ColorButton.grid(row=0, column=4 , padx=2, pady=2,sticky=W)

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        menubar.add_command(label='在浏览器显示结果',command=lambda:open_html('./EXP/output.html'))
        menubar.add_command(label='打开命令执行终端',command=lambda:terminal_infos(gui.root))
        #menubar.add_command(label='打开命令控制台',command=lambda:terminal_cmds(gui.root))
        menubar.add_command(label='刷新EXP脚本',command=RefreshEXP)
        menubar.post(event.x_root,event.y_root)

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动

    def start(self):
        LoadEXP()
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()

#漏洞测试界面类
class Mycheck:
    Get_type = ['GET','POST']#请求类型
    def __init__(self,root,frmCheck):
        self.frmCheck = frmCheck
        self.root = root
        self.columns = ("字段", "值")
        self.Type = ['User-Agent','Connection','Accept-Encoding','Accept']
        self.Value = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0','close','gzip, deflate','*/*']

    def CreateFrm(self):
        #self.frmTOP = Frame(self.frmCheck, width=960, height=25,bg='whitesmoke')#

        self.frmleft_1 = Frame(self.frmCheck, width=480, height=80,bg='white')#
        self.frmleft_2 = Frame(self.frmCheck, width=480, height=250,bg='white')#
        self.frmleft_3 = Frame(self.frmCheck, width=480, height=255,bg='white')#

        self.frmright = Frame(self.frmCheck, width=480, height=590,bg='white')#

        #self.frmTOP.grid(row=0, columnspan=2, padx=1, pady=1)
        self.frmleft_1.grid(row=1, column=0, padx=1, pady=1, sticky="w")
        self.frmleft_2.grid(row=2, column=0, padx=1, pady=1, sticky="w")
        self.frmleft_3.grid(row=3, column=0, padx=1, pady=1, sticky="w")
        self.frmright.grid(row=1, rowspan=3, column=1, padx=1, pady=1, sticky="e")

        #self.frmTOP.grid_propagate(0)
        self.frmleft_1.grid_propagate(0)
        self.frmleft_2.grid_propagate(0)
        self.frmleft_3.grid_propagate(0)
        self.frmright.grid_propagate(0)

    def CreateFirst(self):
        pass
        #self.checkbutton_1 = Button(self.frmTOP, text='发送', width=10, activebackground = "blue", command=lambda :self.thread_it(self._request))
        #self.checkbutton_2 = Button(self.frmTOP, text='生成EXP', width=10, activebackground = "blue", command=lambda :CreateExp(gui.root))
        #self.checkbutton_3 = Button(self.frmTOP, text='SQL注入检测', width=10, activebackground = "red", command=self.check_sql)

        #elf.checkbutton_1.grid(row=0, column=0, padx=2, pady=2, sticky='e')
        #self.checkbutton_2.grid(row=0, column=1, padx=2, pady=2, sticky='e')
        #self.checkbutton_3.grid(row=0, column=2, padx=2, pady=2, sticky='e')

    def CreateSecond(self):
        self.label_1 = Label(self.frmleft_1, text="请求方法")
        self.comboxlist_1 = ttk.Combobox(self.frmleft_1,width='15',textvariable=Ent_C_Top_reqmethod,state='readonly')#请求方法类型
        self.comboxlist_1["values"] = tuple(Mycheck.Get_type)
        self.comboxlist_1.bind("<<ComboboxSelected>>", self.Action_post)

        self.label_2 = Label(self.frmleft_1, text="请求地址")
        self.EntA_1 = Entry(self.frmleft_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=Ent_C_Top_url,font=("consolas",10))#URL

        self.label_3 = Label(self.frmleft_1, text="请求路径")
        self.EntA_2 = Entry(self.frmleft_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=Ent_C_Top_path,font=("consolas",10))#PATH

        self.label_1.grid(row=0, column=0, padx=1, pady=1)
        self.comboxlist_1.grid(row=0, column=1, padx=1, pady=1, sticky='w')
        self.label_2.grid(row=1, column=0, padx=1, pady=1, sticky='w')
        self.EntA_1.grid(row=1, column=1, padx=1, pady=1, sticky='w')
        self.label_3.grid(row=2, column=0, padx=1, pady=1, sticky='w')
        self.EntA_2.grid(row=2, column=1, padx=1, pady=1, sticky='w')
    
    def CreateThird(self):
        self.frmleft_2_1 = Frame(self.frmleft_2, width=400, height=250,bg='whitesmoke')#
        self.frmleft_2_2 = Frame(self.frmleft_2, width=75, height=250,bg='whitesmoke')#

        self.frmleft_2_1.grid(row=0, column=0, padx=1, pady=1)
        self.frmleft_2_2.grid(row=0, column=1, padx=1, pady=1)

        self.frmleft_2_1.grid_propagate(0)
        self.frmleft_2_2.grid_propagate(0)


        self.treeview_1 = ttk.Treeview(self.frmleft_2_1, height=12, show="headings", columns=self.columns)  # 表格

        self.treeview_1.column("字段", width=100, anchor='w')#表示列,不显示
        self.treeview_1.column("值", width=300, anchor='w')
 
        self.treeview_1.heading("字段", text="字段")#显示表头
        self.treeview_1.heading("值", text="值")

        self.treeview_1.bind('<Double-Button-1>', self.set_cell_value) # 双击左键进入编辑

        self.checkbutton_1 = Button(self.frmleft_2_2, text='发   送', width=9, activebackground = "blue", command=lambda :self.thread_it(self._request))
        self.checkbutton_2 = Button(self.frmleft_2_2, text='生成EXP', width=9, activebackground = "blue", command=lambda :CreateExp(gui.root))
        self.checkbutton_3 = Button(self.frmleft_2_2, text='注入检测', width=9, activebackground = "red", command=self.check_sql)

        self.checkbutton_4 = Button(self.frmleft_2_2, text='<-添加', width=9, command=self.newrow)
        self.checkbutton_5 = Button(self.frmleft_2_2, text='<-删除', width=9, command=self.deltreeview)
        self.checkbutton_6 = Button(self.frmleft_2_2, text='清空->', width=9, command=self.delText)

        self.treeview_1.grid(row=0, column=0, padx=1, pady=1)
        self.checkbutton_1.grid(row=0, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_2.grid(row=1, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_3.grid(row=2, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_4.grid(row=3, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_5.grid(row=4, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_6.grid(row=5, column=0, padx=1, pady=1, sticky='n')

        for i in range(min(len(self.Type),len(self.Value))): # 写入数据
            self.treeview_1.insert('', 
                                i, 
                                iid='I00'+str(i+1),
                                values=(self.Type[i], 
                                self.Value[i]))

    def CreateFourth(self):
        self.Text_post = Text(self.frmleft_3, font=("consolas",10), width=65, height=17)
        self.Text_scr = Scrollbar(self.frmleft_3)

        self.Text_post.grid(row=0, column=0, padx=1, pady=1)
        self.Text_scr.grid(row=0, column=1, sticky=S + W + E + N)
        self.Text_scr.config(command=self.Text_post.yview)
        self.Text_post.config(yscrollcommand=self.Text_scr.set)

    def CreateFivth(self):
        self.Text_response = Text(self.frmright, font=("consolas",10), width=64, height=39)
        self.Text_response_scr = Scrollbar(self.frmright)

        self.Text_response.configure(state="disabled")
        self.Text_response.grid(row=0, column=0, padx=1, pady=1)
        self.Text_response_scr.grid(row=0, column=1, sticky=S + W + E + N)
        self.Text_response_scr.config(command=self.Text_response.yview)
        self.Text_response.config(yscrollcommand=self.Text_response_scr.set)

    def Action_post(self,*args):
        if Ent_C_Top_reqmethod.get() == 'POST':
            self.Type.append('Content-Type')
            self.Value.append('application/x-www-form-urlencoded')
            self.treeview_1.insert('', len(self.Type)-1, values=(self.Type[len(self.Type)-1], self.Value[len(self.Type)-1]))
            self.treeview_1.update()
        else:
            for index in self.treeview_1.get_children():
                #a = self.treeview_1.item(index, "values")
                if self.treeview_1.item(index, "values")[0] == 'Content-Type':
                    self.treeview_1.delete(index)
                    self.Type[int(index.replace('I00',''))-1] = None
                    self.Value[int(index.replace('I00',''))-1] = None

    def delText(self):
        self.Text_response.configure(state="normal")
        self.Text_response.delete('1.0','end')
        self.Text_response.configure(state="disabled")

    def newrow(self):
        self.Type.append('字段')
        self.Value.append('值')
        #解决BUG, insert函数如果不指定iid, 则会自动生成item标识, 此操作不会因del而回转生成
        try:
            self.treeview_1.insert('', 'end',
                            iid='I00'+str(len(self.Type)),
                            values=(self.Type[len(self.Type)-1], 
                            self.Value[len(self.Type)-1]))
            self.treeview_1.update()
        except Exception as e:
            self.Type.pop()
            self.Value.pop()

    def deltreeview(self):
        #index_to_delete = []
        for self.item in self.treeview_1.selection():
            self.treeview_1.delete(self.item)
            self.Type[int(self.item.replace('I00',''))-1] = None
            self.Value[int(self.item.replace('I00',''))-1] = None
            #index_to_delete.append(int(self.item.replace('I00',''))-1)
        
        #self.Type = [self.Type[i] for i in range(0, len(self.Type), 1) if i not in index_to_delete]
        #self.Value = [self.Value[i] for i in range(0, len(self.Value), 1) if i not in index_to_delete]
            
    #双击编辑事件
    def set_cell_value(self,event):
        for self.item in self.treeview_1.selection():
        #item = I001
            item_text = self.treeview_1.item(self.item, "values")
            #a = self.treeview_1.item(self.item)
	
        #print(item_text[0:2])  # 输出所选行的值
        self.column= self.treeview_1.identify_column(event.x)# 列
        #row = self.treeview_1.identify_row(event.y)  # 行
        cn = int(str(self.column).replace('#',''))
        rn = math.floor(math.floor(event.y-25)/18)+1
        #rn = int(str(row).replace('I',''))
        self.entryedit = Text(self.frmleft_2_1, font=("consolas",10))
        self.entryedit.insert(INSERT, item_text[cn-1])
        self.entryedit.bind('<FocusOut>',self.saveedit)
        self.entryedit.place(x=(cn-1)*self.treeview_1.column("字段")["width"],
                        y=25+(rn-1)*18,width=self.treeview_1.column(self.columns[cn-1])["width"],
                        height=18)
        
    #文本失去焦点事件
    def saveedit(self,event):
        try:
            self.treeview_1.set(self.item, column=self.column, value=self.entryedit.get(0.0, "end"))
            a = self.treeview_1.set(self.item)
            if self.column.replace('#','') == '1':
                self.Type[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')
            elif self.column.replace('#','') == '2':
                self.Value[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')

        except Exception as e:
            pass
        finally:
            self.entryedit.destroy()

    def handle_post(self,data_post):
        data_dic = {}
        for i in data_post.split('&'):
            j = i.split('=', 1)
            data_dic.update({j[0]:j[1]})
        return data_dic

    def handle_path(self,path):
        #return ['path','path','path']
        path_list = []
        str1= re.findall('=(.*?)&', path+'&') #返回列表组成字符串
        for i in str1:
            path_tmp = path
            path_tmp = path_tmp.replace(i,i+'\'')
            path_list.append(path_tmp.strip('&'))
        return path_list
        #print(path_list)

    def _request(self):
        self.headers = {}
        self.TIMEOUT = 5
        self.Action = Ent_C_Top_reqmethod.get()
        self.url = Ent_C_Top_url.get().strip('\n') + Ent_C_Top_path.get().strip('\n')
        self.data_post = self.Text_post.get(1.0, "end").strip('\n')
        if self.url:
            pass
        else:
            messagebox.showinfo(title='提示', message='请输入目标地址!')
            return

        for index in self.treeview_1.get_children():
            item_text = self.treeview_1.item(index, "values")

            self.headers.update({item_text[0].strip('\n'):item_text[1].strip('\n')})
        #print(globals())
        self.Text_response.configure(state="normal")
        self.Text_response.delete('1.0','end')
        try:
            if self.Action == 'GET':
                self.response = requests.get(url=self.url,
                                    headers=self.headers,
                                    timeout=self.TIMEOUT,
                                    verify=False,
                                    allow_redirects=False)

            elif self.Action == 'POST':
                #POST数据处理
                if self.headers['Content-Type'] == 'application/x-www-form-urlencoded':
                    self.response = requests.post(url=self.url,
                                                headers=self.headers,
                                                #data=self.handle_post(self.data_post),
                                                data=self.data_post,
                                                timeout=self.TIMEOUT,
                                                verify=False,
                                                allow_redirects=False)
                    
                else:
                    self.response = requests.post(url=self.url,
                                                headers=self.headers,
                                                data=self.data_post,
                                                timeout=self.TIMEOUT,
                                                verify=False,
                                                allow_redirects=False)
            else:
                messagebox.showinfo(title='提示', message='暂不支持该方法!')
                return
            self.rawdata = dump.dump_all(self.response,
                                        request_prefix=b'',
                                        response_prefix=b'').decode('utf-8','ignore')
            self.Text_response.delete('1.0','end')
            self.Text_response.insert(INSERT, self.rawdata)
        except requests.exceptions.Timeout as error:
            messagebox.showinfo(title='请求超时', message=error)
        except requests.exceptions.ConnectionError as error:
            messagebox.showinfo(title='请求错误', message=error)
        except KeyError as error:
            messagebox.showinfo(title='提示', message='POST请求需要加上 Content-Type 头部字段!')
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)
        finally:
            self.Text_response.configure(state="disabled")

    def check_sql(self):
        url_list = []
        data_list = []
        url = Ent_C_Top_url.get().strip('\n') + Ent_C_Top_path.get().strip('\n')
        method = Ent_C_Top_reqmethod.get().lower()
        data = mycheck.Text_post.get('0.0','end').strip('\n').replace('\n','\\n')
        header = dict(zip(mycheck.Type, mycheck.Value))
        headers = {}
        for key, value in header.items():
            if key and value:
                headers.update({key : value})

        if method == 'get':
            if '?' not in url:
                messagebox.showinfo(title='提示', message='没有存在参数!')
                return
            path = url[url.index('?')+1:]
            url_http = url[:url.index('?')]+'?'

            temp_path = path.split('&')
            for index in range(len(temp_path)):
                temp_list1 = temp_path.copy()
                temp_list1[index] = temp_path[index] + '\'' 
                url_list.append(url_http+'&'.join(temp_list1) )

            Ss = Sql_scan(headers, TIMEOUT=3)
            dbms_type = list(Ss.rules_dict.keys())
            for url_sql in url_list:
                try:
                    html = Ss.urlopen_get(url_sql)
                    if html == '':
                        continue
                    for dbms in dbms_type:
                        if Ss.check_sql_exis(html, Ss.rules_dict[dbms]):
                            messagebox.showinfo(title='提示', message='数据库类型: ' + dbms + '\n' + '注入参数: ' + url_sql)
                            return
                except Exception as e:
                    continue
            #messagebox.showinfo(title='提示', message='不存在SQL注入!')
            messagebox.showinfo(title='错误', message=str(sys.path))

        elif method == 'post':
            if headers['Content-Type'] == 'application/x-www-form-urlencoded':
                temp_data = data.split('&')
                for index in range(len(temp_data)):
                    temp_list2 = temp_data.copy()
                    temp_list2[index] = temp_data[index] + '\'' 
                    data_list.append('&'.join(temp_list2))

                Ss = Sql_scan(headers, TIMEOUT=3)
                dbms_type = list(Ss.rules_dict.keys())
                for data in data_list:
                    try:
                        html = Ss.urlopen_post(url,data)
                        if html == '':
                            continue
                        for dbms in dbms_type:
                            if Ss.check_sql_exis(html, Ss.rules_dict[dbms]):
                                messagebox.showinfo(title='提示', message='数据库类型: ' + dbms + '\n' + '注入数据: ' + data)
                                return
                    except Exception as e:
                        continue
                messagebox.showinfo(title='提示', message='不存在SQL注入!')
                
            elif headers['Content-Type'] == 'application/json':
                data = mycheck.Text_post.get('0.0','end').strip('\n').replace('\n','\\n')
                try:
                    data_dict = json.loads(data)
                    data_key = list(data_dict.keys())
                    data_list = []
                    for index in data_key:
                        if type(data_dict[index]) == type('str'):
                            temp_dict = data_dict.copy()
                            temp_dict[index] = data_dict[index] + '\''
                            data_list.append(temp_dict)
                except Exception as e:
                    messagebox.showinfo(title='错误', message='json解析失败')
                    return

                Ss = Sql_scan(headers, TIMEOUT=3)
                dbms_type = list(Ss.rules_dict.keys())
                for data in data_list:
                    try:
                        html = Ss.urlopen_post(url,json.dumps(data))
                        if html == '':
                            continue
                        for dbms in dbms_type:
                            if Ss.check_sql_exis(html, Ss.rules_dict[dbms]):
                                messagebox.showinfo(title='提示', message='数据库类型: ' + dbms + '\n' + '注入数据: ' + data)
                                return
                    except Exception as e:
                        continue
                messagebox.showinfo(title='提示', message='不存在SQL注入!')

        else:
            pass
        
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动


    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.CreateFivth()

#根据模板生成EXP类
class CreateExp():
    def __init__(self, root):
        self.Creat = Toplevel(root)
        self.Creat.title("EXP生成")
        self.Creat.geometry('960x605+480+20')
        self.Creat.resizable(width=False, height=False)#不允许扩大
        self.columns = ("变量", "操作", "值", "逻辑")
        self.variable = []
        self.operation = []
        self.Value = []
        self.logic = []
        #self.menubar = Menu(self.Creat)
        #self.menubar.add_command(label = "", command=lambda :TopProxy(gui.root))
        #self.Creat.config(menu = self.menubar)

        #左边
        self.frm_A = Frame(self.Creat, width=500, height=600, bg="white")
        #右边
        self.frm_B = Frame(self.Creat, width=450, height=600, bg="white")
        self.frm_A.grid(row=0, column=0, padx=2, pady=2)
        self.frm_B.grid(row=0, column=1, padx=2, pady=2)
        self.frm_A.grid_propagate(0)
        self.frm_B.grid_propagate(0)

        #左上
        self.frm_A_1 = Frame(self.frm_A, width=500, height=300, bg="white")
        #左下
        self.frm_A_2 = Frame(self.frm_A, width=500, height=300, bg="white")
        self.frm_A_1.grid(row=0, column=0, padx=1, pady=1)
        self.frm_A_2.grid(row=1, column=0, padx=1, pady=1)
        self.frm_A_1.grid_propagate(0)
        self.frm_A_2.grid_propagate(0)

        self.Lab_A_1_1 = Label(self.frm_A_1, text='脚本名称(类名)')#显示
        self.Ent_A_1_1 = Entry(self.frm_A_1, width='45', highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_vulname) #接受输入控件
        self.Lab_A_1_1.grid(row=0, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_1.grid(row=0, column=1,padx=20, pady=10, sticky=W)

        self.Lab_A_1_2 = Label(self.frm_A_1, text='CMS名称')#显示
        self.Ent_A_1_2 = Entry(self.frm_A_1, width='45', highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_cmsname) #接受输入控件
        self.Lab_A_1_2.grid(row=1, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_2.grid(row=1, column=1,padx=20, pady=10, sticky=W)

        self.Lab_A_1_3 = Label(self.frm_A_1, text='CVE编号(函数名)')#显示
        self.Ent_A_1_3 = Entry(self.frm_A_1, width='45', highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_cvename) #接受输入控件
        self.Lab_A_1_3.grid(row=2, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_3.grid(row=2, column=1,padx=20, pady=10, sticky=W)

        self.Lab_A_1_4 = Label(self.frm_A_1, text='版本信息\漏洞描述')#显示
        self.Ent_A_1_4 = Entry(self.frm_A_1, width='45', highlightcolor='red', highlightthickness=1, textvariable=Ent_C_Top_version) #接受输入控件
        self.Lab_A_1_4.grid(row=3, column=0,padx=20, pady=10, sticky=W)
        self.Ent_A_1_4.grid(row=3, column=1,padx=20, pady=10, sticky=W)

        self.Lab_A_1_5 = Label(self.frm_A_1, text='info')#显示
        self.comboxlist_A_1_4 = ttk.Combobox(self.frm_A_1,width=20,textvariable=Ent_C_Top_info,state='readonly') #接受输入控件
        self.comboxlist_A_1_4["values"] = tuple(["[rce]","[deserialization rce]",
                                            "[upload]",
                                            "[deserialization upload]",
                                            "[deserialization]",
                                            "[file contains]",
                                            "[file reading]",
                                            "[xxe]",
                                            "[sql]",
                                            "[ssrf]"])
        self.Lab_A_1_5.grid(row=4, column=0,padx=20, pady=10, sticky=W)
        self.comboxlist_A_1_4.grid(row=4, column=1,padx=20, pady=10, sticky=W)

        #左下左
        self.frm_A_2_1 = Frame(self.frm_A_2, width=425, height=300,bg='whitesmoke')
        #左下右
        self.frm_A_2_2 = Frame(self.frm_A_2, width=75, height=300,bg='whitesmoke')
        self.frm_A_2_1.grid(row=0, column=0,sticky=W)
        self.frm_A_2_2.grid(row=0, column=1,sticky=W)
        self.frm_A_2_1.grid_propagate(0)
        self.frm_A_2_2.grid_propagate(0)

        self.treeview_A_2 = ttk.Treeview(self.frm_A_2_1, height=15, show="headings", columns=self.columns)  # 表格
        self.treeview_A_2.column("变量", width=90, anchor='w')#表示列,不显示
        self.treeview_A_2.column("操作", width=90, anchor='w')
        self.treeview_A_2.column("值", width=200, anchor='w')
        self.treeview_A_2.column("逻辑", width=40, anchor='w')
        self.treeview_A_2.heading("变量", text="变量")#显示表头
        self.treeview_A_2.heading("操作", text="操作")#显示表头
        self.treeview_A_2.heading("值", text="值")#显示表头
        self.treeview_A_2.heading("逻辑", text="逻辑")#显示表头
        self.treeview_A_2.bind('<Double-Button-1>', self.set_cell_value) # 双击左键进入编辑
        self.treeview_A_2.grid(row=0, column=0, padx=1, pady=1)
        
        self.button_1 = Button(self.frm_A_2_2, text='<-添加', width=9, command=self.newrow)
        self.button_2 = Button(self.frm_A_2_2, text='<-删除', width=9, command=self.deltreeview)
        self.button_1.grid(row=0, column=0, padx=1, pady=1, sticky='n')
        self.button_2.grid(row=1, column=0, padx=1, pady=1, sticky='n')

        self.frm_B_1 = Frame(self.frm_B, width=450, height=30, bg="whitesmoke")
        self.frm_B_2 = Frame(self.frm_B, width=450, height=560, bg="whitesmoke")
        self.frm_B_1.grid(row=0, column=0, padx=1, pady=1)
        self.frm_B_2.grid(row=1, column=0, padx=1, pady=1)
        self.frm_B_1.grid_propagate(0)
        self.frm_B_2.grid_propagate(0)

        self.comboxlist_B = ttk.Combobox(self.frm_B_1,width=20,textvariable=Ent_C_Top_template,state='readonly') #接受输入控件
        self.comboxlist_B['values'] = tuple(['POC','EXP'])
        self.comboxlist_B.bind("<<ComboboxSelected>>", self.SelectTemplate)
        self.button_3 = Button(self.frm_B_1, text='生成EXP', width=6, command=self.Creat_from_temp)
        self.button_4 = Button(self.frm_B_1, text='保存EXP', width=6, command=self.Save_from_temp)
        self.comboxlist_B.grid(row=0, column=0, padx=1, pady=1, sticky=W)
        self.button_3.grid(row=0, column=1, padx=1, pady=1, sticky=W)
        self.button_4.grid(row=0, column=2, padx=1, pady=1, sticky=W)

        self.text_B = Text(self.frm_B_2, font=("consolas",10), width=61, height=37)
        self.Scr_B = Scrollbar(self.frm_B_2)  #滚动条控件
        self.text_B.grid(row=0, column=0)
        self.Scr_B.grid(row=0, column=1, sticky=S + W + E + N)
        self.Scr_B.config(command=self.text_B.yview)
        self.text_B.config(yscrollcommand=self.Scr_B.set)


    def Creat_from_temp(self):
        try:
            self.text_B.delete('1.0','end')
            env = Environment(loader=PackageLoader('Template', './'))
            template = env.get_template(self.comboxlist_B.get()+'.j2')
            url = Ent_C_Top_url.get().strip('\n') + Ent_C_Top_path.get().strip('\n')
            if url == '':
                messagebox.showinfo(title='提示', message='没有获取到URL')
                return
            header = dict(zip(mycheck.Type, mycheck.Value))
            headers = {}
            for key, value in header.items():
                if key and value:
                    headers.update({key : value})

            temp_1 = {'Code':'str(r.status_code)', 'HTTP返回头':'str(r.headers)', 'HTTP返回正文':'r.text'}
            temp_2 = {'包含': 'in', 'Not Contains':'not in'}

            var = [temp_1[i] if i in temp_1 else i for i in self.variable]
            oper = [temp_2[i] if i in temp_2 else i for i in self.operation]

            str_2 = ''
            
            for i in range(len(self.Value)):
                if self.logic[i] == None:
                    continue
                elif self.logic[i] == '':
                    str_1 = "r\"" + self.Value[i] + "\"" + " " + oper[i] + " " + var[i]
                    str_2 = str_2 + str_1
                    break
                else:
                    str_1 = "r\"" + self.Value[i] + "\"" + " " + oper[i] + " " + var[i] + " " + self.logic[i].lower() + " "
                    str_2 = str_2 + str_1
            str_2 = "if "+str_2+":"

            service={
                        "entry_nodes":
                            {
                                "vulname": Ent_C_Top_vulname.get().replace(' ','').strip('\n'),
                                "cmsname": Ent_C_Top_cmsname.get().replace(' ','').strip('\n'),
                                "cvename": Ent_C_Top_cvename.get().replace(' ','').strip('\n'),
                                "banner": Ent_C_Top_version.get().strip('\n'),
                                "infoname": Ent_C_Top_info.get(),
                                "condition": str_2.strip('\n')
                            },
                        "header_nodes":
                            {
                                "headinfo":
                                    {
                                        "method": Ent_C_Top_reqmethod.get().lower(),
                                        "path": url[url.index(urlparse(url).netloc)+len(urlparse(url).netloc):],
                                        "header": headers
                                    },
                                "content":
                                    {   "data": mycheck.Text_post.get('0.0','end').strip('\n').replace('\n','\\n')}
                                
                            }
                    }
            content = template.render(service=service)
            self.text_B.insert(INSERT, content)
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)

    def Save_from_temp(self):

        save_data = str(self.text_B.get('0.0','end').strip('\n'))
        if save_data == '':
            messagebox.showinfo(title='提示', message='没有数据')
            return
        try:
            fobj_w = open('./EXP/'+Ent_C_Top_vulname.get()+'.py', 'w',encoding='utf-8')
            fobj_w.writelines(save_data)
            fobj_w.close()
            MyEXP.exp_scripts.append(Ent_C_Top_vulname.get())
            exp.comboxlist_3["values"] = tuple(MyEXP.exp_scripts)
            messagebox.showinfo(title='结果', message='保存成功')
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)



    def SelectTemplate(self,event):
        self.Template_name = './Template/'+self.comboxlist_B.get()+'.j2'
        self.text_B.delete('1.0','end')
        try:
            with open(self.Template_name, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                for i in array: #遍历array中的每个元素
                    self.text_B.insert(INSERT, i)
        except FileNotFoundError as error:
            messagebox.showinfo(title='文件未找到', message=error)
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)
            

    def set_cell_value(self, event):
        item_text = None
        for self.item in self.treeview_A_2.selection():
        #item = I001
            item_text = self.treeview_A_2.item(self.item, "values")
	
        #print(item_text[0:2])  # 输出所选行的值
        self.column= self.treeview_A_2.identify_column(event.x)# 列
        cn = int(str(self.column).replace('#',''))
        rn = math.floor(math.floor(event.y-25)/18)+1

        if cn == 4 and item_text:
            self.tempCom = ttk.Combobox(self.frm_A_2_1, font=("consolas",10), state='readonly')
            self.tempCom['values'] = tuple(['AND','OR',''])
            self.tempCom.current(0)
            self.tempCom.bind("<<ComboboxSelected>>", self.saveCom)

            self.tempCom.place(x=2*self.treeview_A_2.column("变量")["width"]+self.treeview_A_2.column("值")["width"],
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)
        elif cn == 3 and item_text:
            self.entryedit = Text(self.frm_A_2_1, font=("consolas",10))
            self.entryedit.insert(INSERT, item_text[cn-1])
            self.entryedit.bind('<FocusOut>',self.saveentry)
            self.entryedit.place(x=2*self.treeview_A_2.column("变量")["width"],
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)
        elif cn == 2 and item_text:
            self.tempCom = ttk.Combobox(self.frm_A_2_1, font=("consolas",10), state='readonly')
            self.tempCom['values'] = tuple(['包含','Not Contains','==','!=','>','<','>=','<='])
            self.tempCom.current(0)
            self.tempCom.bind("<<ComboboxSelected>>", self.saveCom)

            self.tempCom.place(x=self.treeview_A_2.column("变量")["width"],
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)
        elif cn == 1 and item_text:
            self.tempCom = ttk.Combobox(self.frm_A_2_1, font=("consolas",10), state='readonly')
            self.tempCom['values'] = tuple(['Code','HTTP返回头','HTTP返回正文'])
            self.tempCom.current(0)
            self.tempCom.bind("<<ComboboxSelected>>", self.saveCom)

            self.tempCom.place(x=0,
                            y=25+(rn-1)*18,width=self.treeview_A_2.column(self.columns[cn-1])["width"],
                            height=18)

    def saveentry(self,event):
        try:
            self.treeview_A_2.set(self.item, column=self.column, value=self.entryedit.get(0.0, "end").replace('\n',''))
            #a = self.tempCom.get()
            self.Value[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')

        except Exception as error:
            messagebox.showinfo(title='提示', message=error)
        finally:
            self.entryedit.destroy()

    def saveCom(self,event):
        try:
            self.treeview_A_2.set(self.item, column=self.column, value=self.tempCom.get())
            #a = self.tempCom.get()
            if self.column.replace('#','') == '1':
                self.variable[int(self.item.replace('I00',''))-1] = self.tempCom.get()
            elif self.column.replace('#','') == '2':
                self.operation[int(self.item.replace('I00',''))-1] = self.tempCom.get()
            elif self.column.replace('#','') == '4':
                self.logic[int(self.item.replace('I00',''))-1] = self.tempCom.get()

        except Exception as error:
            messagebox.showinfo(title='提示', message=error)
        finally:
            self.tempCom.destroy()


    def newrow(self):
        self.variable.append('')
        self.operation.append('')
        self.Value.append('')
        self.logic.append('')
        #解决BUG, insert函数如果不指定iid, 则会自动生成item标识, 此操作不会因del而回转
        try:
            self.treeview_A_2.insert('', 'end',
                            iid='I00'+str(len(self.variable)),
                            values=(self.variable[len(self.variable)-1], 
                            self.operation[len(self.variable)-1],
                            self.Value[len(self.variable)-1],
                            self.logic[len(self.variable)-1]))
            self.treeview_A_2.update()
        except Exception as e:
            self.variable.pop()
            self.operation.pop()
            self.Value.pop()
            self.logic.pop()

    def deltreeview(self):
        for self.item in self.treeview_A_2.selection():
            self.treeview_A_2.delete(self.item)
            self.variable[int(self.item.replace('I00',''))-1] = None
            self.operation[int(self.item.replace('I00',''))-1] = None
            self.Value[int(self.item.replace('I00',''))-1] = None
            self.logic[int(self.item.replace('I00',''))-1] = None

class Mynote():
    mynote = None#代表漏洞笔记界面对象
    def __init__(self,root,frmNote):
        self.frmNote = frmNote
        self.root = root
        self.mynotes = self.__dict__
        self.list_1 = []

    def CreateFrm(self):
        self.paned = PanedWindow(self.frmNote, orient="horizontal", showhandle=True, sashrelief="sunken")
        #self.paned.grid(row=0, column=0, padx=1, pady=1)
        self.paned.pack()

        #self.frmleft = Frame(self.paned, width=360,height=600, bg='green')
        self.frmleft = Frame(self.paned, width=360,height=590, bg='white')
        self.frmright = Frame(self.paned, width=580, height=590,bg='white')#

        self.paned.add(self.frmleft)
        self.paned.add(self.frmright)

        self.frmleft.grid_propagate(0)
        self.frmright.grid_propagate(0)

    def Creatleft(self):
        self.tv = ttk.Treeview(self.frmleft, show='tree', height = 32)
        self.ybar=ttk.Scrollbar(self.frmleft, command = self.tv.yview)
        self.tv.configure(yscroll=self.ybar.set)

        #self.tv.heading('#0',text='',anchor='w')
        self.tv.column('#0', width=300, stretch=1)
        self.tv.bind('<Double-Button-1>', self.selectTree)
        self.tv.bind("<Button-3>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件

        self.tv.pack(side=LEFT, fill=BOTH, expand=1)
        self.ybar.pack(side=RIGHT,fill=Y,expand=0)

    def Creatright(self):

        self.Text_note = scrolledtext.ScrolledText(self.frmright, font=("consolas",10), width=85, height=39)
        self.Text_note.pack(fill=X, expand=1)

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        menubar.add_command(label='刷 新',command=self.flushTree)
        menubar.post(event.x_root,event.y_root)

    def flushTree(self):#先删除原先的树, 之后重新构建
        try:
            for item in self.tv.get_children():#删除tree
                self.tv.delete(item)

            for i in list(self.mynotes.keys()):#删除字典存储的数据
                if i.startswith('myid'):
                    del self.mynotes[i]
            self.CreatView()
        except Exception as error:
            messagebox.showinfo(title='出错', message=error)
        
    def CreatView(self):
        self.Getsqldata()
        try:
            for key, value in self.dict_1.items():
                if 'myid'+'_'+key not in self.mynotes:
                    self.mynotes['myid'+'_'+key] = self.tv.insert(
                                                            "", 
                                                            0,
                                                            text = key, 
                                                            values = ('myid'+'_'+key))#""表示父节点是根

                for temp_value in value:
                    for i in range(len(temp_value)):
                        if 'myid'+'_'+key+self.Creat_iid(temp_value,i+1) not in self.mynotes:
                            self.mynotes['myid'+'_'+key+self.Creat_iid(temp_value,i+1)] = self.tv.insert(
                                                                        self.mynotes['myid'+'_'+key+self.Creat_iid(temp_value,i)], 
                                                                        0,
                                                                        text = temp_value[i], 
                                                                        values = ('myid'+'_'+key+self.Creat_iid(temp_value,i+1)))
        except Exception as error:
            messagebox.showinfo(title='出错', message=error)

    def Getsqldata(self):
        self.dict_1 = {}
        try:
            self.conn = pymysql.connect(host='127.0.0.1', user='root',password='123456',database='codetest',charset='utf8')
            # 得到一个可以执行SQL语句的光标对象
            self.cursor = self.conn.cursor(cursor=pymysql.cursors.DictCursor)

            #获取数据库中表信息
            sql_1 = """
                select table_name from information_schema.tables where table_schema = 'codetest';
                """
            self.cursor.execute(sql_1)
            data_1 = self.cursor.fetchall()

            for temp1_dict in data_1:
                list_1 = []
                list_2 = []
                tabname = list(temp1_dict.values())[0]
                sql_2 = """
                    describe %s;
                    """%tabname
                self.cursor.execute(sql_2)
                data_2 = self.cursor.fetchall()

                for temp2_dict in data_2:
                    list_1.append(temp2_dict['Field'])

                sql_3 = """
                    select %s from %s;
                    """%(','.join(list_1[:-1]),tabname)
                self.cursor.execute(sql_3)
                data_3 = self.cursor.fetchall()

                for temp3_dict in data_3:
                    list_2.append(list(temp3_dict.values()))
                dict2 = {tabname: list_2}
                self.dict_1 = {**self.dict_1, **dict2}

        except Exception as error:
            messagebox.showinfo(title='出错', message=error)
        finally:
            self.cursor.close()
            self.conn.close()

    def selectTree(self, event):
        try:
            self.conn = pymysql.connect(host='127.0.0.1', user='root',password='123456',database='codetest',charset='utf8')
            # 得到一个可以执行SQL语句的光标对象
            self.cursor = self.conn.cursor(cursor=pymysql.cursors.DictCursor)
            for item in self.tv.selection():
                item_text = self.tv.item(item, "values")
            search_list = item_text[0].split('_')
            list_1 = []
            list_2 = []

            sql_2 = """
                describe %s;
                """%search_list[1]
            self.cursor.execute(sql_2)
            data_2 = self.cursor.fetchall()

            for temp2_dict in data_2:
                list_1.append(temp2_dict['Field'])
            
            if len(list_1) != len(search_list) - 1:
                #messagebox.showinfo(title='提示', message="不要选择该节点, 请选择最终节点!")
                return

            temp_str = ''
            for i in range(len(list_1[:-1])):
                temp_str = temp_str + list_1[i]+"='"+search_list[i+2]+"' "
            temp_str = temp_str.strip(' ').replace(' ',' and ')

            sql_3 = "select %s from %s where %s;"%(list_1[-1], search_list[1], temp_str)

            self.cursor.execute(sql_3)
            data_3 = self.cursor.fetchall()
            data_3 = list(data_3[0].values())[0]

            self.Text_note.delete('1.0','end')
            self.Text_note.insert(INSERT, data_3)

        except Exception as error:
            messagebox.showinfo(title='出错', message=error)
        finally:
            self.cursor.close()
            self.conn.close()


    def Creat_iid(self, list_, index):
        if index == 0:
            return ''
        temp_list = list_[:index]
        return '_'+'_'.join(temp_list)

    def start(self):
        self.CreateFrm()
        self.Creatleft()
        self.Creatright()
        self.CreatView()

#运行状态线程类
class Job(threading.Thread):
    def __init__(self,*args, **kwargs):
        super(Job, self).__init__(*args, **kwargs)
        self.__flag = threading.Event()   # 用于暂停线程的标识
        self.__flag.set()    # 设置为True
        self.__running = threading.Event()   # 用于停止线程的标识
        self.__running.set()   # 将running设置为True
    def run(self):
        while self.__running.isSet():
            self.__flag.wait()   # 为True时立即返回, 为False时阻塞直到内部的标识位为True后返回
            wait_running()
    def pause(self):
        self.__flag.clear()   # 设置为False, 让线程阻塞
    def resume(self):
        self.__flag.set()  # 设置为True, 让线程停止阻塞
    def stop(self):
        self.__flag.set()    # 将线程从暂停状态恢复, 如何已经暂停的话
        self.__running.clear()    # 设置为False


###全局函数定义###
#调用checkbutton按钮
def callCheckbutton(x,i):
    if MyGUI.var[i].get() == 1:
        try:
            for index in range(len(MyGUI.var)):
                if index != i:
                    MyGUI.var[index].set(0)
            MyGUI.vuln = importlib.import_module('.%s'%x,package='POC')
            MyGUI.Checkbutton_text = x
            print('[*] %s 模块已准备就绪!'%x)
        except Exception as e:
            print('[*]异常对象的内容是:%s'%e)
    else:
        MyGUI.vuln = None
        print('[*] %s 模块已取消!'%x)

#创建POC脚本选择Checkbutton
def Create(frm, x, i):
    MyGUI.threadLock.acquire()
    if int(MyGUI.row) > 18:
        MyGUI.row = 1
    button = Checkbutton(frm,text=x,command=lambda:callCheckbutton(x,i),variable=MyGUI.var[i])
    button.grid(row=MyGUI.row,sticky=W)
    #print(x+'加载成功!')
    MyGUI.row += 1
    MyGUI.threadLock.release()

#填充线程列表,创建多个存储POC脚本的界面, 默认为1, 2, 3, 4
def CreateThread():
    temp_list = []
    for i in range(1,len(MyGUI.scripts)+1):
        temp_list.append(str(math.ceil(i/18)))
    temp_dict = dict(zip(MyGUI.scripts,temp_list))

    for i in range(len(MyGUI.scripts)):
        #scripts_name = scripts[i]
        thread = threading.Thread(target=Create,
        args=(gui.frms['frmD_'+ temp_dict[MyGUI.scripts[i]]],
        MyGUI.scripts[i], i))

        thread.setDaemon(True)
        MyGUI.threadList.append(thread)

#加载POC文件夹下的脚本
def LoadPoc():
    try:
        for _ in glob.glob('POC/*.py'):
            script_name = os.path.basename(_).replace('.py', '')
            if script_name == '__init__':
                continue
            MyGUI.scripts.append(script_name)
            m = IntVar()
            MyGUI.var.append(m)
        CreateThread()

        for t in MyGUI.threadList:
            t.start()
    except Exception as e:
        messagebox.showinfo('提示','请勿重复加载')

#加载EXP文件夹下的脚本
def LoadEXP():
    MyEXP.exp_scripts = MyEXP.exp_scripts[0:1]#清楚脚本列表
    for _ in glob.glob('EXP/*.py'):
        script_name = os.path.basename(_).replace('.py', '')
        if script_name != 'ALL':
            MyEXP.exp_scripts.append(script_name)
    MyEXP.exp_scripts.remove('__init__')

def RefreshEXP():
    try:
        LoadEXP()
        MyEXP.exp_scripts_cve = MyEXP.exp_scripts_cve[0:1]
        x = exp.comboxlist_3.get()
        for func in dir(MyEXP.vuln.__dict__[x]):#获取实际导入的EXP对象
            if not func.startswith("__") and not func.startswith("_"):
                MyEXP.exp_scripts_cve.append(func)#设置具体的CVE漏洞
        exp.comboxlist_3["values"] = tuple(MyEXP.exp_scripts)
        exp.comboxlist_3_1["values"] = tuple(MyEXP.exp_scripts_cve)#设置具体的CVE漏
    except AttributeError:
        messagebox.showinfo('提示','当前还未加载脚本对象!')
    except Exception as e:
        messagebox.showinfo('错误',str(e))

#漏洞利用界面根据漏洞类型显示对应的CVE
def bind_combobox(*args):
    try:
        MyEXP.exp_scripts_cve = ['ALL']
        x = exp.comboxlist_3.get()
        MyEXP.vuln = importlib.import_module('.%s'%x,package='EXP')
        #print(MyEXP.vuln.__dict__)
        for func in dir(MyEXP.vuln.__dict__[x]):#获取实际导入的EXP对象
        #for func in dir(MyEXP.vuln.__dict__[x.lower()]):
            if not func.startswith("__") and not func.startswith("_"):
                MyEXP.exp_scripts_cve.append(func)#设置具体的CVE漏洞
        exp.comboxlist_3_1["values"] = tuple(MyEXP.exp_scripts_cve)#设置具体的CVE漏洞
        print('[*]%s模块已准备就绪!'%x)
    except KeyError:
        exp.comboxlist_3_1["values"] = tuple(MyEXP.exp_scripts_cve)#设置具体的CVE漏洞
        MyEXP.vuln = importlib.import_module('.%s'%x,package='EXP')
        print('[*]%s模块已准备就绪!'%x)
    except Exception as e:
        print('[*]异常对象的内容是:%s'%e)
    finally:
        Ent_B_Top_vulmethod.set("ALL")

def bind_combobox_3(*args):
    x = exp.comboxlist_4.get()
    if x == 'False':
        Ent_B_Bottom_Left_cmd.set('echo VuLnEcHoPoCSuCCeSS')
    else:
        Ent_B_Bottom_Left_cmd.set('whoami')

#当前运行状态
def wait_running():
    MyGUI.wait_index = 0
    list = ["\\", "|", "/", "—"]
    gui.TexA2.configure(state="normal")
    while True:
        index = MyGUI.wait_index % 4
        gui.TexA2.insert(INSERT,list[index])
        time.sleep(0.25)
        gui.TexA2.delete('1.0','end')
        MyGUI.wait_index = MyGUI.wait_index + 1

#打开脚本目录
def LoadCMD(folder_name):
    start_directory = scriptPath + folder_name
    os.startfile(start_directory)

#终止子线程
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

#返回分隔符号函数
def Separator_(str_):
    index = 100 - len(str_)
    left = math.ceil(index/2)
    right = math.floor(index/2)
    return '-'*left + str_ + '-'*right

#复制字符到Windows剪切板
def addToClipboard(text):
    r = Tk()
    r.withdraw()
    r.clipboard_clear()
    r.clipboard_append(text)
    r.update()
    r.destroy()

#显示python搜索环境路径
def ShowPython():
    try:
        print('[*]'+gui.t.getName()+' 运行状态: '+ str(gui.t.isAlive()))
        print('[*]'+gui.t2.getName()+' 运行状态: '+ str(gui.t2.isAlive()))
    except AttributeError:
        messagebox.showinfo(title='提示', message='进程还未启动')
    except Exception as e:
        messagebox.showinfo(title='错误', message=str(e))
        
def save_result():
    #if MyGUI.vul_name != '' and MyGUI.wbswitch == 'true':
    if MyGUI.wbswitch == 'true':
        timestr = time.strftime("%Y%m%d_%H%M%S")#获取当前时间
        print('[*]已保存检测结果 -> %s_%s.xlsx'%(MyGUI.vul_name,timestr))
        MyGUI.wb.save('./result/%s_%s.xlsx'%(MyGUI.vul_name,timestr))
        #清空数据
        MyGUI.wb = None
        MyGUI.ws = None
    else:
        print('[-]未找到批量检测结果, 请先执行脚本测试!')
#重载脚本函数
def ReLoad():
    try:
        MyGUI.vuln = importlib.reload(MyGUI.vuln)
        print('[*]加载成功!')
    except Exception as e:
        messagebox.showinfo(title='提示', message='重新加载失败')
        return
#漏洞笔记界面
def shownote():
    gui.frmPOC.grid_remove()
    gui.frmEXP.grid_remove()
    gui.frmCheck.grid_remove()
    #gui.frmDebug.grid_remove()
    if Mynote.mynote == None:
        Mynote.mynote = Mynote(gui.root, gui.frmNote)
        Mynote.mynote.start()
    gui.frmNote.grid(row=1, column=0, padx=2, pady=2)

#显示漏洞测试界面
def Check():
    gui.frmPOC.grid_remove()
    gui.frmEXP.grid_remove()
    gui.frmNote.grid_remove()
    #gui.frmDebug.grid_remove()
    gui.frmCheck.grid(row=1, column=0, padx=2, pady=2)

#显示漏洞利用界面
def EXP():
    gui.frmPOC.grid_remove()
    gui.frmCheck.grid_remove()
    gui.frmNote.grid_remove()
    #gui.frmDebug.grid_remove()
    gui.frmEXP.grid(row=1, column=0, padx=2, pady=2)
    sys.stdout = TextRedirector(exp.TexBOT_1_2, "stdout", index="2")
    sys.stderr = TextRedirector(exp.TexBOT_1_2, "stderr", index="2")

#显示漏洞扫描界面
def POC():
    gui.frmEXP.grid_remove()
    gui.frmCheck.grid_remove()
    gui.frmNote.grid_remove()
    #gui.frmDebug.grid_remove()
    gui.frmPOC.grid()
    sys.stdout = TextRedirector(gui.TexB, "stdout")
    sys.stderr = TextRedirector(gui.TexB, "stderr")

#创建多个存储POC脚本的界面, 默认为1, 2, 3, 4
def Area_POC(index):
    for i in range(1,5):
        gui.frms['frmD_'+str(i)].grid_remove()
    gui.frms['frmD_'+str(index)].grid(row=1, column=1, padx=2, pady=2)

#删除text组件的内容
def delText(text):
    text.configure(state="normal")
    text.delete('1.0','end')
    text.configure(state="disabled")

#漏洞利用界面执行命令函数
def exeCMD(**kwargs):
    if MyEXP.vuln == None:
        messagebox.showinfo(title='提示', message='还未选择模块')
        return
    kwargs['status'] = 'fail'
    start = time.time()
    exp.color_switch('green')
    #now = datetime.datetime.now()
    #print("["+str(now)[11:19]+"] " + "[*] 开始执行测试")
    print("[*]开始执行测试: %s"%kwargs['url'].strip('/'))
    #多模块测试
    if kwargs['url']:
        #单目标执行
        try:
            kwargs['url'] = kwargs['url'].strip('/')
            MyEXP.vuln.check(**kwargs)
        except Exception as e:
            print('出现错误: %s'%e)
        exp.color_switch('red')
        end = time.time()
        #now = datetime.datetime.now()
        #print("["+str(now)[11:19]+"] " + "[*] 共花费时间：{} 秒".format(seconds2hms(end - start)))
        print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
        return
    elif MyGUI.now_text.strip('\n'):
        file_list = [i for i in MyGUI.now_text.split("\n") if i!='']#去空处理
        executor = ThreadPoolExecutor(max_workers = 3)
        dict_list = []#存储字典参数列表
        url_list = []#存储目标列表
        index_list = []#索引列表
        type_list = []#脚本名称列表
        result_list = []#存储结果列表
        name = MyEXP.vuln.__name__.replace('EXP.','')
        index = 1
        for url in file_list:
            dict_temp = kwargs.copy()
            dict_temp['url'] = url.strip('/')
            url_list.append(url)
            dict_list.append(dict_temp)
            index_list.append(index)
            type_list.append(name)
            index += 1
        try:
            for data in executor.map(lambda kwargs: MyEXP.vuln.check(**kwargs), dict_list):
                result_list.append(data+'\n')#汇聚结果
        except Exception as e:
            result_list.append('请求发生异常, 请删除该URL')
        #for i in range(len(url_list)):
        #    index_list.append(i+1)
        #    type_list.append(name)
        #index_list = [i+1 for i in range(len(url_list))]
        print_result = zip(index_list, type_list, file_list, result_list)#合并列表
        #根据结果生成表格
        tb = pt.PrettyTable()
        tb.field_names = ["Index", "Type", "URL", "Result"]
        tb.align['Type'] = 'l'
        tb.align['URL'] = 'l'
        tb.align['Result'] = 'l'
        for i in print_result:
            tb.add_row(i)
        print(tb)
        #MyEXP.output = tb.get_html_string()
        with open('./EXP/output.html', "wb") as f:
            f.write(tb.get_html_string().encode('utf8'))
        exp.color_switch('red')
        end = time.time()
        #now = datetime.datetime.now()
        #print("["+str(now)[11:19]+"] " + "[*] 共花费时间：{} 秒".format(seconds2hms(end - start)))
        print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
    else:
        color('[*]请输入目标URL!','red')
        color('[*]请输入目标URL!','yellow')
        color('[*]请输入目标URL!','blue')
        color('[*]请输入目标URL!','green')
        color('[*]请输入目标URL!','orange')
        color('[*]请输入目标URL!','pink')
        color('[*]请输入目标URL!','cyan')


#预留功能函数
def note():
    messagebox.showinfo('提示','预留功能')

#退出时执行的函数
def callbackClose():
    if messagebox.askokcancel('提示','要执行此操作吗?') == True:
        try:
            save_data = str(exp.TexB1.get('0.0','end'))
            fobj_w = open('./lib/note.txt', 'w',encoding='utf-8')
            fobj_w.writelines(save_data)
            fobj_w.close()
            sys.exit(0)
            #gui.root.destroy()
        except Exception as e:
            messagebox.showerror(title='保存文件错误!', message=e)

#全局函数定义结束

#全局环境变量
github_now = None #保存GitHub登录后的状态

if __name__ == "__main__":
    gui = MyGUI()

    #全局定义组件宽度
    s = ttk.Style()
    s.configure('Treeview', rowheight=18) # repace 40 with whatever you need
    s.configure('red.TSeparator',background='red')

    #导入变量
    from settings import Proxy_type,Proxy_CheckVar1,Proxy_CheckVar2,Proxy_addr,Proxy_port, scriptPath, curPath,\
        Ent_A_Top_thread, Ent_A_Top_Text, \
        Ent_B_Top_url,Ent_B_Top_cookie,Ent_B_Top_vulname,Ent_B_Top_vulmethod,Ent_B_Top_funtype,Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Bottom_Left_cmd,Ent_B_Bottom_terminal_cmd, \
        Ent_C_Top_url,Ent_C_Top_path,Ent_C_Top_reqmethod,Ent_C_Top_vulname,Ent_C_Top_cmsname,Ent_C_Top_cvename,Ent_C_Top_version,Ent_C_Top_info,Ent_C_Top_template, \
        Ent_Cmds_Top_type,Ent_Cmds_Top_typevar, \
        Ent_yso_Top_type,Ent_yso_Top_class,Ent_yso_Top_cmd, \
        TCP_Debug_IP,TCP_Debug_PORT,TCP_Debug_PKT_BUFF_SIZE, \
        variable_dict,Proxy_web
    #初始化全局变量
    GlobalVar._init()
    #初始化全局代理变量
    os.environ['HTTP_PROXY'] = ''
    os.environ['HTTPS_PROXY'] = ''
    #生初始化漏洞扫描界面    
    gui.start()
    #生成漏洞利用界面
    exp = MyEXP(gui.root,gui.frmEXP)
    exp.start()
    #生成漏洞测试界面
    mycheck = Mycheck(gui.root, gui.frmCheck)
    mycheck.start()
    #输出重定向
    sys.stdout = TextRedirector(gui.TexB, "stdout")
    sys.stderr = TextRedirector(gui.TexB, "stderr")
    gui.TexB.insert(INSERT, Ent_A_Top_Text)  #INSERT表示输入光标所在的位置，初始化后的输入光标默认在左上角
    #自定义退出函数
    gui.root.protocol("WM_DELETE_WINDOW", callbackClose)
    gui.root.mainloop()