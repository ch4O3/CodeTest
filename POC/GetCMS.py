from urllib.parse import urlparse
import copy
import time,urllib3
import types
import re,random,requests
#from lib.URL_getCMS_lib import ruleDatas
urllib3.disable_warnings()

ruleDatas = {
    "Shiro": {
        "regex": "(=deleteMe|rememberMe=)",
        "type": "headers",
    },
    "宝塔-BT.cn": {
        "regex": "(app.bt.cn/static/app.png|安全入口校验失败)",
        "type": "bodys",
    },
    "Nexus": {
        "regex": "(<title>Nexus Repository Manager</title>)",
        "type": "bodys",
    },
    "Harbor": {
        "regex": "(<title>Harbor</title>)",
        "type": "bodys",
    },
    "禅道": {
        "regex": "(/theme/default/images/main/zt-logo.png)",
        "type": "bodys",
    },
    "xxl-job": {
        "regex": "(分布式任务调度平台XXL-JOB)",
        "type": "bodys",
    },
    "weblogic": {
        "regex": "(/console/framework/skins/wlsconsole/images/login_WebLogic_branding.png|Welcome to Weblogic Application Server|<i>Hypertext Transfer Protocol -- HTTP/1.1</i>)",
        "type": "bodys",
    },
    "用友致远oa": {
        "regex": "(/seeyon/USER-DATA/IMAGES/LOGIN/login.gif)",
        "type": "bodys",
    },
    "Typecho": {
        "regex": "(Typecho</a>)",
        "type": "bodys",
    },
    "金蝶EAS": {
        "regex": "(easSessionId)",
        "type": "bodys",
    },
    "phpMyAdmin": {
        "regex": "(/themes/pmahomme/img/logo_right.png)",
        "type": "bodys",
    },
    "H3C-AM8000": {
        "regex": "(AM8000)",
        "type": "bodys",
    },
    "360企业版": {
        "regex": "(360EntWebAdminMD5Secret)",
        "type": "bodys",
    },
    "H3C ICG 1000": {
        "regex": "(ICG 1000系统管理)",
        "type": "bodys",
    },
    "Citrix-Metaframe": {
        "regex": "(window.location=\\\"/Citrix/MetaFrame)",
        "type": "bodys",
    },
    "H3C ER5100": {
        "regex": "(ER5100系统管理)",
        "type": "bodys",
    },
    "阿里云CDN": {
        "regex": "(cdn.aliyuncs.com)",
        "type": "bodys",
    },
    "CISCO_EPC3925": {
        "regex": "(Docsis_system)",
        "type": "bodys",
    },
    "CISCO ASR": {
        "regex": "(CISCO ASR)",
        "type": "bodys",
    },
    "H3C ER3200": {
        "regex": "(ER3200系统管理)",
        "type": "bodys",
    },
    "万户ezOFFICE": {
        "regex": "(LocLan)",
        "type": "headers",
    },
    "万户网络": {
        "regex": "(css/css_whir.css)",
        "type": "bodys",
    },
    "Spark_Master": {
        "regex": "(Spark Master at)",
        "type": "bodys",
    },
    "华为_HUAWEI_SRG2220": {
        "regex": "(HUAWEI SRG2220)",
        "type": "bodys",
    },
    "蓝凌EIS智慧协同平台": {
        "regex": "(/scripts/jquery.landray.common.js)",
        "type": "bodys",
    },
    "深信服ssl-vpn": {
        "regex": "(login_psw.csp)",
        "type": "bodys",
    },
    "华为 NetOpen": {
        "regex": "(/netopen/theme/css/inFrame.css)",
        "type": "bodys",
    },
    "Citrix-Web-PN-Server": {
        "regex": "(Citrix Web PN Server)",
        "type": "bodys",
    },
    "juniper_vpn": {
        "regex": "(welcome.cgi\\?p=logo|/images/logo_juniper_reversed.gif)",
        "type": "bodys",
    },
    "Nagios": {
        "regex": "(Nagios Access)",
        "type": "headers",
    },
    "H3C ER8300": {
        "regex": "(ER8300系统管理)",
        "type": "bodys",
    },
    "Citrix-Access-Gateway": {
        "regex": "(Citrix Access Gateway)",
        "type": "bodys",
    },
    "华为 MCU": {
        "regex": "(McuR5-min.js)",
        "type": "bodys",
    },
    "TP-LINK Wireless WDR3600": {
        "regex": "(TP-LINK Wireless WDR3600)",
        "type": "bodys",
    },
    "泛微协同办公OA": {
        "regex": "(ecology_JSessionid)",
        "type": "headers",
    },
    "华为_HUAWEI_ASG2050": {
        "regex": "(HUAWEI ASG2050)",
        "type": "bodys",
    },
    "360网站卫士": {
        "regex": "(360wzb)",
        "type": "bodys",
    },
    "Citrix-XenServer": {
        "regex": "(Citrix Systems, Inc. XenServer)",
        "type": "bodys",
    },
    "H3C ER2100V2": {
        "regex": "(ER2100V2系统管理)",
        "type": "bodys",
    },
    "zabbix": {
        "regex": "(images/general/zabbix.ico)",
        "type": "bodys",
    },
    "CISCO_VPN": {
        "regex": "(webvpn)",
        "type": "headers",
    },
    "360站长平台": {
        "regex": "(360-site-verification)",
        "type": "bodys",
    },
    "H3C ER3108GW": {
        "regex": "(ER3108GW系统管理)",
        "type": "bodys",
    },
    "o2security_vpn": {
        "regex": "(client_param=install_active)",
        "type": "headers",
    },
    "H3C ER3260G2": {
        "regex": "(ER3260G2系统管理)",
        "type": "bodys",
    },
    "H3C ICG1000": {
        "regex": "(ICG1000系统管理)",
        "type": "bodys",
    },
    "CISCO-CX20": {
        "regex": "(CISCO-CX20)",
        "type": "bodys",
    },
    "H3C ER5200": {
        "regex": "(ER5200系统管理)",
        "type": "bodys",
    },
    "linksys-vpn-bragap14-parintins": {
        "regex": "(linksys-vpn-bragap14-parintins)",
        "type": "bodys",
    },
    "360网站卫士常用前端公共库": {
        "regex": "(libs.useso.com)",
        "type": "bodys",
    },
    "H3C ER3100": {
        "regex": "(ER3100系统管理)",
        "type": "bodys",
    },
    "H3C-SecBlade-FireWall": {
        "regex": "(js/MulPlatAPI.js)",
        "type": "bodys",
    },
    "360webfacil_360WebManager": {
        "regex": "(publico/template/)",
        "type": "bodys",
    },
    "Citrix_Netscaler": {
        "regex": "(ns_af)",
        "type": "bodys",
    },
    "H3C ER6300G2": {
        "regex": "(ER6300G2系统管理)",
        "type": "bodys",
    },
    "H3C ER3260": {
        "regex": "(ER3260系统管理)",
        "type": "bodys",
    },
    "华为_HUAWEI_SRG3250": {
        "regex": "(HUAWEI SRG3250)",
        "type": "bodys",
    },
    "exchange": {
        "regex": "(/owa/auth.owa)",
        "type": "bodys",
    },
    "Spark_Worker": {
        "regex": "(Spark Worker at)",
        "type": "bodys",
    },
    "H3C ER3108G": {
        "regex": "(ER3108G系统管理)",
        "type": "bodys",
    },
    "深信服防火墙类产品": {
        "regex": "(SANGFOR FW)",
        "type": "bodys",
    },
    "Citrix-ConfProxy": {
        "regex": "(confproxy)",
        "type": "bodys",
    },
    "360网站安全检测": {
        "regex": "(webscan.360.cn/status/pai/hash)",
        "type": "bodys",
    },
    "H3C ER5200G2": {
        "regex": "(ER5200G2系统管理)",
        "type": "bodys",
    },
    "华为(HUAWEI)安全设备": {
        "regex": "(sweb-lib/resource/)",
        "type": "bodys",
    },
    "H3C ER6300": {
        "regex": "(ER6300系统管理)",
        "type": "bodys",
    },
    "华为_HUAWEI_ASG2100": {
        "regex": "(HUAWEI ASG2100)",
        "type": "bodys",
    },
    "TP-Link 3600 DD-WRT": {
        "regex": "(TP-Link 3600 DD-WRT)",
        "type": "bodys",
    },
    "NETGEAR WNDR3600": {
        "regex": "(NETGEAR WNDR3600)",
        "type": "bodys",
    },
    "H3C ER2100": {
        "regex": "(ER2100系统管理)",
        "type": "bodys",
    },
    "绿盟下一代防火墙": {
        "regex": "(NSFOCUS NF)",
        "type": "bodys",
    },
    "jira": {
        "regex": "(jira.webresources)",
        "type": "bodys",
    },
    "金和协同管理平台": {
        "regex": "(金和协同管理平台)",
        "type": "bodys",
    },
    "Citrix-NetScaler": {
        "regex": "(NS-CACHE)",
        "type": "bodys",
    },
    "linksys-vpn": {
        "regex": "(linksys-vpn)",
        "type": "headers",
    },
    "通达OA": {
        "regex": "(/static/images/tongda.ico)",
        "type": "bodys",
    },
    "华为Secoway设备": {
        "regex": "(Secoway)",
        "type": "bodys",
    },
    "华为_HUAWEI_SRG1220": {
        "regex": "(HUAWEI SRG1220)",
        "type": "bodys",
    },
    "H3C ER2100n": {
        "regex": "(ER2100n系统管理)",
        "type": "bodys",
    },
    "H3C ER8300G2": {
        "regex": "(ER8300G2系统管理)",
        "type": "bodys",
    },
    "金蝶政务GSiS": {
        "regex": "(/kdgs/script/kdgs.js)",
        "type": "bodys",
    },
    "Jboss": {
        "regex": "(Welcome to JBoss|jboss.css)",
        "type": "bodys",
    },
    "Spring": {
        "regex": "(Whitelabel Error Page)",
        "type": "bodys",
    },
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    #########################################
    "Dell-Printer": {
        "regex": "(Dell Laser Printer)",
        "type": "headers",
    },

    "HP-OfficeJet-Printer": {
        "regex": "(HP Officejet | align=center>HP Officejet)",
        "type": "bodys",
    },

    "Biscom-Delivery-Server": {
        "regex": "(/bds/stylesheets/fds.css | /bds/includes/fdsJavascript.do)",
        "type": "bodys",
    },

    "DD-WRT": {
        "regex": "(style/pwc/ddwrt.css)",
        "type": "bodys",
    },

    "ewebeditor": {
        "regex": "(/ewebeditor.htm?)",
        "type": "bodys",
    },

    "fckeditor": {
        "regex": "(new FCKeditor)",
        "type": "bodys",
    },

    "xheditor": {
        "regex": "(xheditor_lang/zh-cn.js|class=xheditor|.xheditor)",
        "type": "bodys",
    },

    "百为路由": {
        "regex": "(提交验证的id必须是ctl_submit)",
        "type": "bodys",
    },

    "锐捷NBR路由器": {
        "regex": "(free_nbr_login_form.png)",
        "type": "bodys",
    },

    "mikrotik": {
        "regex": "(RouterOS | mikrotik)",
        "type": "bodys",
    },

    "ThinkSNS": {
        "regex": "(/addons/theme/)",
        "type": "bodys",
    },

    "h3c路由器": {
        "regex": "(Web user login | nLanguageSupported)",
        "type": "bodys",
    },

    "jcg无线路由器": {
        "regex": "(Wireless Router | http://www.jcgcn.com)",
        "type": "bodys",
    },

    "D-Link_VoIP_Wireless_Router": {
        "regex": "(D-Link VoIP Wireless Router)",
        "type": "headers",
    },

    "arrisi_Touchstone": {
        "regex": "(Touchstone Status | passWithWarnings)",
        "type": "bodys",
    },

    "ZyXEL": {
        "regex": "(Forms/rpAuth_1)",
        "type": "bodys",
    },

    "Ruckus": {
        "regex": "(mon.  Tell me your username | Ruckus Wireless Admin)",
        "type": "bodys",
    },

    "Motorola_SBG900": {
        "regex": "(Motorola SBG900)",
        "type": "headers",
    },

    "Wimax_CPE": {
        "regex": "(Wimax CPE Configuration)",
        "type": "headers",
    },

    "Cisco_Cable_Modem": {
        "regex": "(Cisco Cable Modem)",
        "type": "headers",
    },

    "Scientific-Atlanta_Cable_Modem": {
        "regex": "(Scientific-Atlanta Cable Modem)",
        "type": "headers",
    },

    "rap": {
        "regex": "(/jscripts/rap_util.js)",
        "type": "bodys",
    },

    "ZTE_MiFi_UNE": {
        "regex": "(MiFi UNE 4G LTE)",
        "type": "headers",
    },

    "ZTE_ZSRV2_Router": {
        "regex": "(ZSRV2路由器Web管理系统 | ZTE Corporation. All Rights Reserved.)",
        "type": "bodys",
    },

    "百为智能流控路由器": {
        "regex": "(BYTEVALUE 智能流控路由器 | <a href=http://www.bytevalue.com/ target=_blank>)",
        "type": "bodys",
    },

    "乐视路由器": {
        "regex": "(乐视路由器 | <div class=login-logo></div>)",
        "type": "bodys",
    },

    "Verizon_Wireless_Router": {
        "regex": "(Wireless Broadband Router Management Console | body = verizon_logo_blk.gif)",
        "type": "bodys",
    },

    "Nexus_NX_router": {
        "regex": "(http://nexuswifi.com/ | Nexus NX)",
        "type": "bodys",
    },

    "Verizon_Router": {
        "regex": "(Verizon Router)",
        "type": "headers",
    },

    "小米路由器": {
        "regex": "(小米路由器 )",
        "type": "headers",
    },

    "QNO_Router": {
        "regex": "(/QNOVirtual_Keyboard.js | /images/login_img01_03.gif)",
        "type": "bodys",
    },

    "爱快流控路由": {
        "regex": "(爱快 | /resources/images/land_prompt_ico01.gif)",
        "type": "bodys",
    },

    "Django": {
        "regex": "(__admin_media_prefix__ | csrfmiddlewaretoken)",
        "type": "bodys",
    },

    "axis2-web": {
        "regex": "(axis2-web/css/axis-style.css)",
        "type": "bodys",
    },

    "Apache-Wicket": {
        "regex": "(xmlns:wicket= | /org.apache.wicket.)",
        "type": "bodys",
    },

    "BEA-WebLogic-Server": {
        "regex": "(<h1>BEA WebLogic Server | WebLogic)",
        "type": "bodys",
    },

    "EDK": {
        "regex": "(<!-- /killlistable.tpl -->)",
        "type": "bodys",
    },

    "eDirectory": {
        "regex": "(target=_blank>eDirectory&trade | Powered by <a href=http://www.edirectory.com)",
        "type": "bodys",
    },

    "Esvon-Classifieds": {
        "regex": "(Powered by Esvon)",
        "type": "bodys",
    },

    "Fluid-Dynamics-Search-Engine": {
        "regex": "(content=fluid dynamics)",
        "type": "bodys",
    },

    "mongodb": {
        "regex": "(<a href=/_replSet>Replica set status</a></p>)",
        "type": "bodys",
    },

    "MVB2000": {
        "regex": "(MVB2000 | The Magic Voice Box)",
        "type": "bodys",
    },

    "GPSweb": {
        "regex": "(GPSweb)",
        "type": "headers",
    },

    "phpinfo": {
        "regex": "(phpinfo | Virtual Directory Support )",
        "type": "bodys",
    },

    "lemis管理系统": {
        "regex": "(lemis.WEB_APP_NAME)",
        "type": "bodys",
    },

    "FreeboxOS": {
        "regex": "(Freebox OS | logo_freeboxos)",
        "type": "bodys",
    },

    "Wimax_CPE": {
        "regex": "(Wimax CPE Configuration)",
        "type": "headers",
    },

    "Scientific-Atlanta_Cable_Modem": {
        "regex": "(Scientific-Atlanta Cable Modem)",
        "type": "headers",
    },

    "rap": {
        "regex": "(/jscripts/rap_util.js)",
        "type": "bodys",
    },

    "ZTE_MiFi_UNE": {
        "regex": "(MiFi UNE 4G LTE)",
        "type": "headers",
    },

    "用友商战实践平台": {
        "regex": "(Login_Main_BG | Login_Owner)",
        "type": "bodys",
    },

    "moosefs": {
        "regex": "(mfs.cgi | under-goal files)",
        "type": "bodys",
    },

    "蓝盾BDWebGuard": {
        "regex": "(BACKGROUND: urlimages/loginbg.jpg #e5f1fc)",
        "type": "bodys",
    },

    "护卫神网站安全系统": {
        "regex": "(护卫神.网站安全系统)",
        "type": "headers",
    },

    "phpDocumentor": {
        "regex": "(Generated by phpDocumentor)",
        "type": "bodys",
    },

    "Adobe_ CQ5": {
        "regex": "(_jcr_content)",
        "type": "bodys",
    },

    "Adobe_GoLive": {
        "regex": "(generator content=Adobe GoLive)",
        "type": "bodys",
    },

    "Adobe_RoboHelp": {
        "regex": "(generator content=Adobe RoboHelp)",
        "type": "bodys",
    },

    "Amaya": {
        "regex": "(generator content=Amaya)",
        "type": "bodys",
    },

    "OpenMas": {
        "regex": "(OpenMas | loginHead><link href=App_Themes)",
        "type": "bodys",
    },

    "recaptcha": {
        "regex": "(recaptcha_ajax.js)",
        "type": "bodys",
    },

    "TerraMaster": {
        "regex": "(TerraMaster)",
        "type": "bodys",
    },

    "创星伟业校园网群": {
        "regex": "(vcxvcxv)",
        "type": "bodys",
    },

    "正方教务管理系统": {
        "regex": "(style/base/jw.css)",
        "type": "bodys",
    },

    "UFIDA_NC": {
        "regex": "(UFIDA | logo/images/ | logo/images/ufida_nc.png)",
        "type": "bodys",
    },

    "北创图书检索系统": {
        "regex": "(opac_two)",
        "type": "bodys",
    },

    "北京清科锐华CEMIS": {
        "regex": "(/theme/2009/image | login.asp)",
        "type": "bodys",
    },

    "RG-PowerCache内容加速系统": {
        "regex": "(RG-PowerCache)",
        "type": "headers",
    },

    "sugon_gridview": {
        "regex": "(/common/resources/images/common/app/gridview.ico)",
        "type": "bodys",
    },

    "SLTM32_Configuration": {
        "regex": "(SLTM32 Web Configuration Pages )",
        "type": "headers",
    },

    "SHOUTcast": {
        "regex": "(SHOUTcast Administrator)",
        "type": "headers",
    },

    "milu_seotool": {
        "regex": "(plugin.php?id=milu_seotool)",
        "type": "bodys",
    },

    "CISCO_EPC3925": {
        "regex": "(Docsis_system | EPC3925)",
        "type": "bodys",
    },

    "HP_iLO(HP_Integrated_Lights-Out)": {
        "regex": "(js/iLO.js)",
        "type": "bodys",
    },

    "Siemens_SIMATIC": {
        "regex": "(/S7Web.css)",
        "type": "bodys",
    },

    "Schneider_Quantum_140NOE77101": {
        "regex": "(indexLanguage | html/config.js)",
        "type": "bodys",
    },

    "lynxspring_JENEsys": {
        "regex": "(LX JENEsys)",
        "type": "bodys",
    },

    "Sophos_Web_Appliance": {
        "regex": "(Sophos Web Appliance)",
        "type": "headers",
    },

    "Comcast_Business": {
        "regex": "(cmn/css/common-min.css)",
        "type": "bodys",
    },

    "Locus_SolarNOC": {
        "regex": "(SolarNOC - Login)",
        "type": "headers",
    },

    "Everything": {
        "regex": "(Everything.gif|everything.png | Everything)",
        "type": "bodys",
    },

    "honeywell NetAXS": {
        "regex": "(Honeywell NetAXS)",
        "type": "headers",
    },

    "Symantec Messaging Gateway": {
        "regex": "(Messaging Gateway)",
        "type": "headers",
    },

    "xfinity": {
        "regex": "(Xfinity | /reset-meyer-1.0.min.css)",
        "type": "bodys",
    },

    "网动云视讯平台": {
        "regex": "(Acenter | /js/roomHeight.js | meetingShow!show.action)",
        "type": "bodys",
    },

    "蓝凌EIS智慧协同平台": {
        "regex": "(/scripts/jquery.landray.common.js | v11_QRcodeBar clr)",
        "type": "bodys",
    },

    "金山KingGate": {
        "regex": "(/src/system/login.php)",
        "type": "bodys",
    },

    "天融信入侵检测系统TopSentry": {
        "regex": "(天融信入侵检测系统TopSentry)",
        "type": "headers",
    },

    "天融信日志收集与分析系统": {
        "regex": "(天融信日志收集与分析系统)",
        "type": "headers",
    },

    "天融信WEB应用防火墙": {
        "regex": "(天融信WEB应用防火墙)",
        "type": "headers",
    },

    "天融信入侵防御系统TopIDP": {
        "regex": "(天融信入侵防御系统TopIDP)",
        "type": "bodys",
    },

    "天融信Web应用安全防护系统": {
        "regex": "(天融信Web应用安全防护系统)",
        "type": "headers",
    },

    "天融信TopFlow": {
        "regex": "(天融信TopFlow)",
        "type": "bodys",
    },

    "汉码软件": {
        "regex": "(汉码软件 | alt=汉码软件LOGO | content=汉码软件)",
        "type": "bodys",
    },

    "凡科": {
        "regex": "(凡科互联网科技股份有限公司 | content=凡科)",
        "type": "bodys",
    },

    "易分析": {
        "regex": "(易分析 PHPStat Analytics | PHPStat Analytics 网站数据分析系统)",
        "type": "bodys",
    },

    "phpems考试系统": {
        "regex": "(phpems | content=PHPEMS)",
        "type": "bodys",
    },

    "智睿软件": {
        "regex": "(content=智睿软件 | Zhirui.js)",
        "type": "bodys",
    },

    "Apabi数字资源平台": {
        "regex": "(Default/apabi.css | <link href=HTTP://apabi | 数字资源平台)",
        "type": "bodys",
    },

    "Fortinet Firewall": {
        "regex": "(Firewall Notification)",
        "type": "headers",
    },

    "WDlinux": {
        "regex": "(wdOS)",
        "type": "headers",
    },

    "小脑袋": {
        "regex": "(http://stat.xiaonaodai.com/stat.php)",
        "type": "bodys",
    },

    "天融信ADS管理平台": {
        "regex": "(天融信ADS管理平台)",
        "type": "headers",
    },

    "天融信异常流量管理与抗拒绝服务系统": {
        "regex": "(天融信异常流量管理与抗拒绝服务系统)",
        "type": "headers",
    },

    "天融信网络审计系统": {
        "regex": "(onclick=dlg_download)",
        "type": "bodys",
    },

    "天融信脆弱性扫描与管理系统": {
        "regex": "(天融信脆弱性扫描与管理系统 | /js/report/horizontalReportPanel.js)",
        "type": "bodys",
    },

    "AllNewsManager_NET": {
        "regex": "(Powered by AllNewsManager)",
        "type": "bodys",
    },

    "Advanced-Image-Hosting-Script": {
        "regex": "(yabsoft.com  | Welcome to install AIHS Script)",
        "type": "bodys",
    },

    "SNB股票交易软件": {
        "regex": "(Copyright 2005–2009 <a href=http://www.s-mo.com>)",
        "type": "bodys",
    },

    "AChecker Web accessibility evaluation tool": {
        "regex": "(content=AChecker is a Web accessibility | Checker : Web Accessibility Checker)",
        "type": "bodys",
    },

    "SCADA PLC": {
        "regex": "(/images/rockcolor.gif | /ralogo.gif | Ethernet Processor)",
        "type": "bodys",
    },

    ".NET": {
        "regex": "(content=Visual Basic .NET 7.1)",
        "type": "bodys",
    },

    "phpmoadmin": {
        "regex": "(phpmoadmin)",
        "type": "headers",
    },

    "SOMOIDEA": {
        "regex": "(DESIGN BY SOMOIDEA)",
        "type": "bodys",
    },

    "Apache-Archiva": {
        "regex": "(Apache Archiva | /archiva.js | /archiva.css)",
        "type": "bodys",
    },

    "AM4SS": {
        "regex": "(Powered by am4ss | am4ss.css)",
        "type": "bodys",
    },

    "ASPThai_Net-Webboard": {
        "regex": "(ASPThai.Net Webboard)",
        "type": "bodys",
    },

    "Astaro-Command-Center": {
        "regex": "(/acc_aggregated_reporting.js | /js/_variables_from_backend.js?)",
        "type": "bodys",
    },

    "ASP-Nuke": {
        "regex": "(CONTENT=ASP-Nuke | content=ASPNUKE)",
        "type": "bodys",
    },

    "ASProxy": {
        "regex": "(Surf the web invisibly using ASProxy power | btnASProxyDisplayButton)",
        "type": "bodys",
    },

    "ashnews": {
        "regex": "(powered by ashnews)",
        "type": "bodys",
    },

    "Arab-Portal": {
        "regex": "(Powered by: Arab)",
        "type": "bodys",
    },

    "AppServ": {
        "regex": "(appserv/softicon.gif | index.php?appservlang=th)",
        "type": "bodys",
    },

    "VZPP Plesk": {
        "regex": "(VZPP Plesk )",
        "type": "headers",
    },

    "ApPHP-Calendar": {
        "regex": "(This script was generated by ApPHP Calendar)",
        "type": "bodys",
    },

    "BigDump": {
        "regex": "(BigDump | BigDump: Staggered MySQL Dump Importer)",
        "type": "bodys",
    },

    "BestShopPro": {
        "regex": "(content=www.bst.pl)",
        "type": "bodys",
    },

    "BASE": {
        "regex": "(<!-- Basic Analysis and Security Engine BASE --> | mailto:base@secureideas.net)",
        "type": "bodys",
    },

    "Basilic": {
        "regex": "(/Software/Basilic)",
        "type": "bodys",
    },

    "Basic-PHP-Events-Lister": {
        "regex": "(Powered by: <a href=http://www.mevin.com/>)",
        "type": "bodys",
    },

    "AV-Arcade": {
        "regex": "(Powered by <a href=http://www.avscripts.net/avarcade/)",
        "type": "bodys",
    },

    "Auxilium-PetRatePro": {
        "regex": "(index.php?cmd=11)",
        "type": "bodys",
    },

    "Axis-PrintServer": {
        "regex": "(psb_printjobs.gif | /cgi-bin/prodhelp?prod=)",
        "type": "bodys",
    },

    "TeamViewer": {
        "regex": "(This site is running|TeamViewer)",
        "type": "bodys",
    },

    "BlueQuartz": {
        "regex": "(VALUE=Copyright C 2000, Cobalt Networks | Login - BlueQuartz)",
        "type": "bodys",
    },

    "BlueOnyx": {
        "regex": "(Login - BlueOnyx | Thank you for using the BlueOnyx)",
        "type": "bodys",
    },

    "BMC-Remedy": {
        "regex": "(Remedy Mid Tier)",
        "type": "headers",
    },

    "BM-Classifieds": {
        "regex": "(<!-- START HEADER TABLE - HOLDS GRAPHIC AND SITE NAME -->)",
        "type": "bodys",
    },

    "Citrix-Metaframe": {
        "regex": "(window.location=/Citrix/MetaFrame)",
        "type": "bodys",
    },

    "Cogent-DataHub": {
        "regex": "(/images/Cogent.gif | Cogent DataHub WebView)",
        "type": "bodys",
    },

    "ClipShare": {
        "regex": "(<!--!!!!!!!!!!!!!!!!!!!!!!!!! Processing SCRIPT | Powered By <a href=http://www.clip-share.com)",
        "type": "bodys",
    },

    "CGIProxy": {
        "regex": "(<a href=http://www.jmarshall.com/tools/cgiproxy/)",
        "type": "bodys",
    },

    "CF-Image-Hosting-Script": {
        "regex": "(Powered By <a href=http://codefuture.co.uk/projects/imagehost/)",
        "type": "bodys",
    },

    "Censura": {
        "regex": "(Powered by: <a href=http://www.censura.info)",
        "type": "bodys",
    },

    "CA-SiteMinder": {
        "regex": "(<!-- SiteMinder Encoding)",
        "type": "bodys",
    },

    "Carrier-CCNWeb": {
        "regex": "(/images/CCNWeb.gif | <APPLET CODE=JLogin.class ARCHIVE=JLogin.jar)",
        "type": "bodys",
    },

    "cInvoice": {
        "regex": "(Powered by <a href=http://www.forperfect.com/)",
        "type": "bodys",
    },

    "Bomgar": {
        "regex": "(alt=Remote Support by BOMGAR | <a href=http://www.bomgar.com/products class=inverse)",
        "type": "bodys",
    },

    "cApexWEB": {
        "regex": "(/capexweb.parentvalidatepassword | name=dfparentdb)",
        "type": "bodys",
    },

    "CameraLife": {
        "regex": "(content=Camera Life | This site is powered by Camera Life)",
        "type": "bodys",
    },

    "CalendarScript": {
        "regex": "(Calendar Administration : Login | Powered by <A HREF=http://www.CalendarScript.com)",
        "type": "bodys",
    },

    "Cachelogic-Expired-Domains-Script": {
        "regex": "(href=http://cachelogic.net>Cachelogic.net)",
        "type": "bodys",
    },

    "Burning-Board-Lite": {
        "regex": "(Powered by <b><a href=http://www.woltlab.de | Powered by <b>Burning Board)",
        "type": "bodys",
    },

    "Buddy-Zone": {
        "regex": "(Powered By <a href=http://www.vastal.com | >Buddy Zone</a>)",
        "type": "bodys",
    },

    "Bulletlink-Newspaper-Template": {
        "regex": "(/ModalPopup/core-modalpopup.css | powered by bulletlink)",
        "type": "bodys",
    },

    "Brother-Printer": {
        "regex": "(<FRAME SRC=/printer/inc_head.html | <IMG src=/common/image/HL4040CN)",
        "type": "bodys",
    },

    "Daffodil-CRM": {
        "regex": "(Powered by Daffodil | Design & Development by Daffodil Software Ltd)",
        "type": "bodys",
    },

    "Cyn_in": {
        "regex": "(content=cyn.in | Powered by cyn.in)",
        "type": "bodys",
    },

    "Oracle_OPERA": {
        "regex": "(MICROS Systems Inc., OPERA | OperaLogin/Welcome.do)",
        "type": "bodys",
    },

    "DUgallery": {
        "regex": "(Powered by DUportal |  DUgallery)",
        "type": "bodys",
    },

    "DublinCore": {
        "regex": "(name=DC.title)",
        "type": "bodys",
    },

    "DVWA": {
        "regex": "(Damn Vulnerable Web App DVWA - Login | dvwa/css/login.css | dvwa/images/login_logo.png)",
        "type": "bodys",
    },

    "DORG": {
        "regex": "(DORG -  | CONTENT=DORG)",
        "type": "bodys",
    },

    "VOS3000": {
        "regex": "(VOS3000|<meta name=keywords content=VOS3000|<meta name=description content=VOS3000|images/vos3000.ico)",
        "type": "bodys",
    },

    "Elite-Gaming-Ladders": {
        "regex": "(Powered by Elite)",
        "type": "bodys",
    },

    "Entrans": {
        "regex": "(Entrans)",
        "type": "headers",
    },

    "GateQuest-PHP-Site-Recommender": {
        "regex": "(GateQuest)",
        "type": "headers",
    },

    "Gallarific": {
        "regex": "(content=Gallarific | Gallarific > Sign in)",
        "type": "bodys",
    },

    "EZCMS": {
        "regex": "(Powered by EZCMS | EZCMS Content Management System)",
        "type": "bodys",
    },

    "Etano": {
        "regex": "(Powered by <a href=http://www.datemill.com | Etano</a>. All Rights Reserved.)",
        "type": "bodys",
    },

    "GeoServer": {
        "regex": "(/org.geoserver.web.GeoServerBasePage/ | class=geoserver lebeg)",
        "type": "bodys",
    },

    "GeoNode": {
        "regex": "(Powered by <a href=http://geonode.org | href=/catalogue/opensearch GeoNode Search)",
        "type": "bodys",
    },

    "Help-Desk-Software": {
        "regex": "(target=_blank>freehelpdesk.org)",
        "type": "bodys",
    },

    "GridSite": {
        "regex": "(<a href=http://www.gridsite.org/>GridSite | gridsite-admin.cgi?cmd)",
        "type": "bodys",
    },

    "GenOHM-SCADA": {
        "regex": "(GenOHM Scada Launcher | /cgi-bin/scada-vis/)",
        "type": "bodys",
    },

    "Infomaster": {
        "regex": "(/MasterView.css | /masterView.js | /MasterView/MPLeftNavStyle/PanelBar.MPIFMA.css)",
        "type": "bodys",
    },

    "Imageview": {
        "regex": "(content=Imageview | By Jorge Schrauwen | href=http://www.blackdot.be Blackdot.be)",
        "type": "bodys",
    },

    "Ikonboard": {
        "regex": "(content=Ikonboard | Powered by <a href=http://www.ikonboard.com)",
        "type": "bodys",
    },

    "i-Gallery": {
        "regex": "(i-Gallery | href=igallery.asp)",
        "type": "bodys",
    },

    "OrientDB": {
        "regex": "(Redirecting to OrientDB)",
        "type": "headers",
    },

    "Apache-Solr": {
        "regex": "(Solr Admin|SolrCore Initialization Failures|app_config.solr_path)",
        "type": "bodys",
    },

    "Inout-Adserver": {
        "regex": "(Powered by Inoutscripts)",
        "type": "bodys",
    },

    "ionCube-Loader": {
        "regex": "(alt=ionCube logo)",
        "type": "bodys",
    },

    "Jamroom": {
        "regex": "(content=Talldude Networks | content=Jamroom)",
        "type": "bodys",
    },

    "Juniper-NetScreen-Secure-Access": {
        "regex": "(/dana-na/auth/welcome.cgi)",
        "type": "bodys",
    },

    "Jcow": {
        "regex": "(content=Jcow | content=Powered by Jcow | end jcow_application_box)",
        "type": "bodys",
    },

    "InvisionPowerBoard": {
        "regex": "(Powered by <a href=http://www.invisionboard.com)",
        "type": "bodys",
    },

    "teamportal": {
        "regex": "(TS_expiredurl)",
        "type": "bodys",
    },

    "VisualSVN": {
        "regex": "(VisualSVN Server)",
        "type": "headers",
    },

    "Redmine": {
        "regex": "(Redmine | authenticity_token)",
        "type": "bodys",
    },

    "testlink": {
        "regex": "(testlink_library.js)",
        "type": "bodys",
    },

    "mantis": {
        "regex": "(browser_search_plugin.php?type=id | MantisBT Team)",
        "type": "bodys",
    },

    "Mercurial": {
        "regex": "(Mercurial repositories index)",
        "type": "headers",
    },

    "activeCollab": {
        "regex": "(powered by activeCollab | <p id=powered_by><a href=http://www.activecollab.com/)",
        "type": "bodys",
    },

    "Collabtive": {
        "regex": "(Login @ Collabtive)",
        "type": "headers",
    },

    "CGI:IRC": {
        "regex": "(CGI:IRC Login | <!-- This is part of CGI:IRC | <small id=ietest><a href=http://cgiirc.org/)",
        "type": "bodys",
    },

    "DotA-OpenStats": {
        "regex": "(content=dota OpenStats | content=openstats.iz.rs)",
        "type": "bodys",
    },

    "eLitius": {
        "regex": "(content=eLitius | target=_blank Affiliate)",
        "type": "bodys",
    },

    "gCards": {
        "regex": "(<a href=http://www.gregphoto.net/gcards/index.php)",
        "type": "bodys",
    },

    "GpsGate-Server": {
        "regex": "(GpsGate Server - )",
        "type": "headers",
    },

    "iScripts-ReserveLogic": {
        "regex": "(Powered by <a href=http://www.iscripts.com/reservelogic/)",
        "type": "bodys",
    },

    "jobberBase": {
        "regex": "(http://www.jobberbase.com | Jobber.PerformSearch | content=Jobberbase)",
        "type": "bodys",
    },

    "LuManager": {
        "regex": "(LuManager)",
        "type": "headers",
    },

    "主机宝": {
        "regex": "(您访问的是主机宝服务器默认页)",
        "type": "bodys",
    },

    "wdcp管理系统": {
        "regex": "(wdcp服务器 | lanmp_wdcp 安装成功)",
        "type": "headers",
    },

    "LANMP一键安装包": {
        "regex": "(LANMP一键安装包)",
        "type": "headers",
    },

    "UPUPW": {
        "regex": "(UPUPW环境集成包)",
        "type": "headers",
    },

    "wamp": {
        "regex": "(WAMPSERVER)",
        "type": "headers",
    },

    "easypanel": {
        "regex": "(/vhost/view/default/style/login.css)",
        "type": "bodys",
    },

    "awstats_admin": {
        "regex": "(generator content=AWStats | <frame name=mainleft src=awstats.pl?config=)",
        "type": "bodys",
    },

    "awstats": {
        "regex": "(awstats.pl?config=)",
        "type": "bodys",
    },

    "moosefs": {
        "regex": "(mfs.cgi | under-goal files)",
        "type": "bodys",
    },

    "护卫神主机管理": {
        "regex": "(护卫神·主机管理系统)",
        "type": "headers",
    },

    "bacula-web": {
        "regex": "(Webacula | Bacula Web | Bacula-Web | bacula-web)",
        "type": "headers",
    },

    "Webmin": {
        "regex": "(Login to Webmin | Webmin server on)",
        "type": "bodys",
    },

    "Synology_DiskStation": {
        "regex": "(Synology DiskStation | SYNO.SDS.Session)",
        "type": "bodys",
    },

    "Puppet_Node_Manager": {
        "regex": "(Puppet Node Manager)",
        "type": "headers",
    },

    "wdcp": {
        "regex": "(wdcp服务器)",
        "type": "headers",
    },

    "Citrix-XenServer": {
        "regex": "(Citrix Systems, Inc. XenServer | <a href=XenCenterSetup.exe>XenCenter installer</a>)",
        "type": "bodys",
    },

    "DSpace": {
        "regex": "(content=DSpace | <a href=http://www.dspace.org>DSpace Software)",
        "type": "bodys",
    },

    "dwr": {
        "regex": "(/dwr/engine.js)",
        "type": "bodys",
    },

    "eXtplorer": {
        "regex": "(Login - eXtplorer)",
        "type": "headers",
    },

    "File-Upload-Manager": {
        "regex": "(File Upload Manager | <IMG SRC=/images/header.jpg ALT=File Upload Manager>)",
        "type": "bodys",
    },

    "FileNice": {
        "regex": "(content=the fantabulous mechanical eviltwin code machine | fileNice/fileNice.js)",
        "type": "bodys",
    },

    "Glossword": {
        "regex": "(content=Glossword)",
        "type": "bodys",
    },

    "IBM-BladeCenter": {
        "regex": "(/shared/ibmbch.png | /shared/ibmbcs.png | alt=IBM BladeCenter)",
        "type": "bodys",
    },

    "iLO": {
        "regex": "(href=http://www.hp.com/go/ilo | HP Integrated Lights-Out)",
        "type": "bodys",
    },

    "Isolsoft-Support-Center": {
        "regex": "(Powered by: Support Center)",
        "type": "bodys",
    },

    "ISPConfig": {
        "regex": "(powered by <a HREF=http://www.ispconfig.org)",
        "type": "bodys",
    },

    "Kleeja": {
        "regex": "(Powered by Kleeja)",
        "type": "bodys",
    },

    "Kloxo-Single-Server": {
        "regex": "(src=/img/hypervm-logo.gif | /htmllib/js/preop.js | HyperVM)",
        "type": "bodys",
    },

    "易瑞授权访问系统": {
        "regex": "(/authjsp/login.jsp | FE0174BB-F093-42AF-AB20-7EC621D10488)",
        "type": "bodys",
    },

    "MVB2000": {
        "regex": "(MVB2000 | The Magic Voice Box)",
        "type": "bodys",
    },

    "NetShare_VPN": {
        "regex": "(NetShare | VPN)",
        "type": "headers",
    },

    "pmway_E4_crm": {
        "regex": "(E4 | CRM)",
        "type": "headers",
    },

    "srun3000计费认证系统": {
        "regex": "(srun3000)",
        "type": "headers",
    },

    "Dolibarr": {
        "regex": "(Dolibarr Development Team)",
        "type": "bodys",
    },

    "Parallels Plesk Panel": {
        "regex": "(Parallels IP Holdings GmbH)",
        "type": "bodys",
    },

    "EasyTrace(botwave)": {
        "regex": "(EasyTrace | login_page)",
        "type": "bodys",
    },

    "管理易": {
        "regex": "(管理易 | minierp)",
        "type": "bodys",
    },

    "亿赛通DLP": {
        "regex": "(CDGServer3)",
        "type": "bodys",
    },

    "huawei_auth_server": {
        "regex": "(75718C9A-F029-11d1-A1AC-00C04FB6C223)",
        "type": "bodys",
    },

    "瑞友天翼_应用虚拟化系统 ": {
        "regex": "(瑞友天翼－应用虚拟化系统)",
        "type": "headers",
    },

    "360企业版": {
        "regex": "(360EntInst)",
        "type": "bodys",
    },

    "用友erp-nc": {
        "regex": "(/nc/servlet/nc.ui.iufo.login.Index | 用友新世纪)",
        "type": "bodys",
    },

    "Array_Networks_VPN": {
        "regex": "(an_util.js)",
        "type": "bodys",
    },

    "juniper_vpn": {
        "regex": "(welcome.cgi?p=logo)",
        "type": "bodys",
    },

    "CEMIS": {
        "regex": "(<div id=demo style=overflow:hidden | 综合项目管理系统登录)",
        "type": "bodys",
    },

    "zenoss": {
        "regex": "(/zport/dmd/)",
        "type": "bodys",
    },

    "OpenMas": {
        "regex": "(OpenMas | loginHead><link href=App_Themes)",
        "type": "bodys",
    },

    "Ultra_Electronics": {
        "regex": "(/preauth/login.cgi | /preauth/style.css)",
        "type": "bodys",
    },

    "NOALYSS": {
        "regex": "(NOALYSS)",
        "type": "headers",
    },

    "ALCASAR": {
        "regex": "(valoriserDiv5)",
        "type": "bodys",
    },

    "orocrm": {
        "regex": "(/bundles/oroui/)",
        "type": "bodys",
    },

    "Adiscon_LogAnalyzer": {
        "regex": "(Adiscon LogAnalyzer | Adiscon LogAnalyzer | Adiscon GmbH)",
        "type": "bodys",
    },

    "Munin": {
        "regex": "(Auto-generated by Munin | munin-month.html)",
        "type": "bodys",
    },

    "MRTG": {
        "regex": "(Command line is easier to read using View Page Properties of your browser | MRTG Index Page | commandline was: indexmaker)",
        "type": "bodys",
    },

    "元年财务软件": {
        "regex": "(yuannian.css | /image/logo/yuannian.gif)",
        "type": "bodys",
    },

    "UFIDA_NC": {
        "regex": "(UFIDA | logo/images/ | logo/images/ufida_nc.png)",
        "type": "bodys",
    },

    "Webmin": {
        "regex": "(Login to Webmin | Webmin server on)",
        "type": "bodys",
    },

    "锐捷应用控制引擎": {
        "regex": "(window.open/login.do,airWin | 锐捷应用控制引擎)",
        "type": "bodys",
    },

    "Storm": {
        "regex": "(Storm UI | stormtimestr)",
        "type": "bodys",
    },

    "Centreon": {
        "regex": "(Generator content=Centreon - Copyright | Centreon - IT & Network Monitoring)",
        "type": "bodys",
    },

    "FortiGuard": {
        "regex": "(FortiGuard Web Filtering | Web Filter Block Override | /XX/YY/ZZ/CI/MGPGHGPGPFGHCDPFGGOGFGEH)",
        "type": "bodys",
    },

    "PineApp": {
        "regex": "(PineApp WebAccess - Login | /admin/css/images/pineapp.ico)",
        "type": "bodys",
    },

    "CDR-Stats": {
        "regex": "(CDR-Stats | Customer Interface | /static/cdr-stats/js/jquery)",
        "type": "bodys",
    },

    "GenieATM": {
        "regex": "(GenieATM | Copyright© Genie Networks Ltd. | defect 3531)",
        "type": "bodys",
    },

    "Spark_Worker": {
        "regex": "(Spark Worker at)",
        "type": "headers",
    },

    "Spark_Master": {
        "regex": "(Spark Master at)",
        "type": "headers",
    },

    "Kibana": {
        "regex": "(Kibana | kbnVersion)",
        "type": "bodys",
    },

    "UcSTAR": {
        "regex": "(UcSTAR 管理控制台)",
        "type": "headers",
    },

    "i@Report": {
        "regex": "(ESENSOFT_IREPORT_SERVER | com.sanlink.server.Login | ireportclient | css/ireport.css)",
        "type": "bodys",
    },

    "帕拉迪统一安全管理和综合审计系统": {
        "regex": "(module/image/pldsec.css)",
        "type": "bodys",
    },

    "openEAP": {
        "regex": "(openEAP_统一登录门户)",
        "type": "headers",
    },

    "Dorado": {
        "regex": "(Dorado Login Page)",
        "type": "headers",
    },

    "金龙卡金融化一卡通网站查询子系统": {
        "regex": "(金龙卡金融化一卡通网站查询子系统 | location.href=homeLogin.action)",
        "type": "bodys",
    },

    "一采通": {
        "regex": "(/custom/GroupNewsList.aspx?GroupId=)",
        "type": "bodys",
    },

    "埃森诺网络服务质量检测系统": {
        "regex": "(埃森诺网络服务质量检测系统 )",
        "type": "headers",
    },

    "惠尔顿上网行为管理系统": {
        "regex": "(updateLoginPswd.php | PassroedEle)",
        "type": "bodys",
    },

    "ACSNO网络探针": {
        "regex": "(探针管理与测试系统-登录界面)",
        "type": "headers",
    },

    "绿盟下一代防火墙": {
        "regex": "(NSFOCUS NF)",
        "type": "headers",
    },

    "用友U8": {
        "regex": "(getFirstU8Accid)",
        "type": "bodys",
    },

    "华为（HUAWEI）安全设备": {
        "regex": "(sweb-lib/resource/)",
        "type": "bodys",
    },

    "网神防火墙": {
        "regex": "(secgate 3600 | css/lsec/login.css)",
        "type": "bodys",
    },

    "cisco UCM": {
        "regex": "(/ccmadmin/ | Cisco Unified)",
        "type": "bodys",
    },

    "panabit智能网关": {
        "regex": "(panabit)",
        "type": "headers",
    },

    "久其通用财表系统": {
        "regex": "(<nobr>北京久其软件股份有限公司 | /netrep/intf | /netrep/message2/)",
        "type": "bodys",
    },

    "soeasy网站集群系统": {
        "regex": "(EGSS_User | SoEasy网站集群)",
        "type": "bodys",
    },

    "畅捷通": {
        "regex": "(畅捷通)",
        "type": "headers",
    },

    "科来RAS": {
        "regex": "(科来网络回溯 | 科来软件 版权所有 | i18ninit.min.js)",
        "type": "bodys",
    },

    "科迈RAS系统": {
        "regex": "(科迈RAS | type=application/npRas | 远程技术支持请求：<a href=http://www.comexe.cn)",
        "type": "bodys",
    },

    "单点CRM系统": {
        "regex": "(URL=general/ERP/LOGIN/ | content=单点CRM系统 |客户关系管理-CRM)",
        "type": "bodys",
    },

    "中国期刊先知网": {
        "regex": "(本系统由<span class=STYLE1 ><a href=http://www.firstknow.cn | <img src=images/logoknow.png)",
        "type": "bodys",
    },

    "loyaa信息自动采编系统": {
        "regex": "(/Loyaa/common.lib.js)",
        "type": "bodys",
    },

    "浪潮政务系统": {
        "regex": "(OnlineQuery/QueryList.aspx | 浪潮政务 | LangChao.ECGAP.OutPortal)",
        "type": "bodys",
    },

    "悟空CRM": {
        "regex": "(悟空CRM | /Public/js/5kcrm.js)",
        "type": "bodys",
    },

    "用友ufida": {
        "regex": "(/System/Login/Login.asp?AppID=)",
        "type": "bodys",
    },

    "金蝶EAS": {
        "regex": "(easSessionId)",
        "type": "bodys",
    },

    "金蝶政务GSiS": {
        "regex": "(/kdgs/script/kdgs.js)",
        "type": "bodys",
    },

    "网御上网行为管理系统": {
        "regex": "(Leadsec ACM)",
        "type": "headers",
    },

    "ZKAccess 门禁管理系统": {
        "regex": "(/logoZKAccess_zh-cn.jpg)",
        "type": "bodys",
    },

    "福富安全基线管理": {
        "regex": "(align=center>福富软件)",
        "type": "bodys",
    },

    "中控智慧时间安全管理平台": {
        "regex": "(ZKECO 时间&安全管理平台)",
        "type": "headers",
    },

    "天融信安全管理系统": {
        "regex": "(天融信安全管理)",
        "type": "headers",
    },

    "锐捷 RG-DBS": {
        "regex": "(/css/impl-security.css | /dbaudit/authenticate)",
        "type": "bodys",
    },

    "深信服防火墙类产品": {
        "regex": "(SANGFOR FW)",
        "type": "bodys",
    },

    "天融信网络卫士过滤网关": {
        "regex": "(天融信网络卫士过滤网关)",
        "type": "headers",
    },

    "天融信网站监测与自动修复系统": {
        "regex": "(天融信网站监测与自动修复系统)",
        "type": "headers",
    },

    "天融信 TopAD": {
        "regex": "(天融信 TopAD)",
        "type": "headers",
    },

    "Apache-Forrest": {
        "regex": "(content=Apache Forrest | name=Forrest)",
        "type": "bodys",
    },

    "Advantech-WebAccess": {
        "regex": "(/bw_templete1.dwt | /broadweb/WebAccessClientSetup.exe | /broadWeb/bwuconfig.asp)",
        "type": "bodys",
    },

    "URP教务系统": {
        "regex": "(URP 综合教务系统 | 北京清元优软科技有限公司)",
        "type": "bodys",
    },

    "H3C公司产品": {
        "regex": "(service@h3c.com | H3C Corporation | icg_helpScript.js)",
        "type": "bodys",
    },

    "Huawei HG520 ADSL2+ Router": {
        "regex": "(Huawei HG520)",
        "type": "headers",
    },

    "Huawei B683V": {
        "regex": "(Huawei B683V)",
        "type": "headers",
    },

    "HUAWEI ESPACE 7910": {
        "regex": "(HUAWEI ESPACE 7910)",
        "type": "headers",
    },

    "Huawei HG630": {
        "regex": "(Huawei HG630)",
        "type": "headers",
    },

    "Huawei B683": {
        "regex": "(Huawei B683)",
        "type": "headers",
    },

    "华为 MCU": {
        "regex": "(McuR5-min.js | MCUType.js | huawei MCU)",
        "type": "bodys",
    },

    "HUAWEI Inner Web": {
        "regex": "(HUAWEI Inner Web | hidden_frame.html)",
        "type": "bodys",
    },

    "HUAWEI CSP": {
        "regex": "(HUAWEI CSP)",
        "type": "headers",
    },

    "华为 NetOpen": {
        "regex": "(/netopen/theme/css/inFrame.css | Huawei NetOpen System)",
        "type": "bodys",
    },

    "校园卡管理系统": {
        "regex": "(Harbin synjones electronic | document.FormPostds.action=xxsearch.action | /shouyeziti.css)",
        "type": "bodys",
    },

    "OBSERVA telcom": {
        "regex": "(OBSERVA)",
        "type": "headers",
    },

    "汉柏安全网关": {
        "regex": "(OPZOON - )",
        "type": "headers",
    },

    "b2evolution": {
        "regex": "(/powered-by-b2evolution-150t.gif | Powered by b2evolution | content=b2evolution)",
        "type": "bodys",
    },

    "AvantFAX": {
        "regex": "(content=Web 2.0 HylaFAX | images/avantfax-big.png)",
        "type": "bodys",
    },

    "Aurion": {
        "regex": "(<!-- Aurion Teal will be used as the login-time default | /aurion.js)",
        "type": "bodys",
    },

    "Cisco-IP-Phone": {
        "regex": "(Cisco Unified Wireless IP Phone)",
        "type": "bodys",
    },

    "Cisco-VPN-3000-Concentrator": {
        "regex": "(Cisco Systems, Inc. VPN 3000 Concentrator)",
        "type": "headers",
    },

    "BugTracker.NET": {
        "regex": "(href=btnet.css | valign=middle><a href=http://ifdefined.com/bugtrackernet.html> | <div class=logo>BugTracker.NET)",
        "type": "bodys",
    },

    "BugFree": {
        "regex": "(id=logo alt=BugFree | class=loginBgImage alt=BugFree |  BugFree | name=BugUserPWD)",
        "type": "bodys",
    },

    "cPassMan": {
        "regex": "(Collaborative Passwords Manager)",
        "type": "headers",
    },

    "splunk": {
        "regex": "(Splunk.util.normalizeBoolean)",
        "type": "bodys",
    },

    "DrugPak": {
        "regex": "(Powered by DrugPak | /dplimg/DPSTYLE.CSS)",
        "type": "bodys",
    },

    "DMXReady-Portfolio-Manager": {
        "regex": "(/css/PortfolioManager/styles_display_page.css | rememberme_portfoliomanager)",
        "type": "bodys",
    },

    "eGroupWare": {
        "regex": "(content=eGroupWare)",
        "type": "bodys",
    },

    "eSyndiCat": {
        "regex": "(content=eSyndiCat)",
        "type": "bodys",
    },

    "Epiware": {
        "regex": "(Epiware - Project and Document Management)",
        "type": "bodys",
    },

    "eMeeting-Online-Dating-Software": {
        "regex": "(eMeeting Dating Software | /_eMeetingGlobals.js)",
        "type": "bodys",
    },

    "FreeNAS": {
        "regex": "(Welcome to FreeNAS | /images/ui/freenas-logo.png)",
        "type": "bodys",
    },

    "FestOS": {
        "regex": "(FestOS | css/festos.css)",
        "type": "bodys",
    },

    "eTicket": {
        "regex": "(Powered by eTicket | <a href=http://www.eticketsupport.com target=_blank> | /eticket/eticket.css)",
        "type": "bodys",
    },

    "FileVista": {
        "regex": "(Welcome to FileVista | <a href=http://www.gleamtech.com/products/filevista/web-file-manager)",
        "type": "bodys",
    },

    "Google-Talk-Chatback": {
        "regex": "(www.google.com/talk/service/)",
        "type": "bodys",
    },

    "Flyspray": {
        "regex": "(Powered by Flyspray)",
        "type": "bodys",
    },

    "HP-StorageWorks-Library": {
        "regex": "(HP StorageWorks)",
        "type": "headers",
    },

    "HostBill": {
        "regex": "(Powered by <a href=http://hostbillapp.com | <strong>HostBill)",
        "type": "bodys",
    },

    "IBM-Cognos": {
        "regex": "(/cgi-bin/cognos.cgi | Cognos &#26159; International Business Machines Corp)",
        "type": "bodys",
    },

    "iTop": {
        "regex": "(iTop Login | href=http://www.combodo.com/itop)",
        "type": "bodys",
    },

    "Kayako-SupportSuite": {
        "regex": "(Powered By Kayako eSupport | Help Desk Software By Kayako eSupport)",
        "type": "bodys",
    },

    "JXT-Consulting": {
        "regex": "(id=jxt-popup-wrapper | Powered by JXT Consulting)",
        "type": "bodys",
    },

    "Fastly cdn": {
        "regex": "(fastcdn.org)",
        "type": "bodys",
    },

    "JBoss_AS": {
        "regex": "(Manage this JBoss AS Instance)",
        "type": "bodys",
    },

    "oracle_applicaton_server": {
        "regex": "(OraLightHeaderSub)",
        "type": "bodys",
    },

    "Avaya-Aura-Utility-Server": {
        "regex": "(vmsTitle>Avaya Aura&#8482;&nbsp;Utility Server | /webhelp/Base/Utility_toc.htm)",
        "type": "bodys",
    },

    "DnP Firewall": {
        "regex": "(Powered by DnP Firewall | dnp_firewall_redirect)",
        "type": "bodys",
    },

    "PaloAlto_Firewall": {
        "regex": "(Access to the web page you were trying to visit has been blocked in accordance with company policy)",
        "type": "bodys",
    },

    "梭子鱼防火墙": {
        "regex": "(http://www.barracudanetworks.com?a=bsf_product class=transbutton | /cgi-mod/header_logo.cgi)",
        "type": "bodys",
    },

    "IndusGuard_WAF": {
        "regex": "(IndusGuard WAF | body = wafportal/wafportal.nocache.js)",
        "type": "bodys",
    },

    "网御WAF": {
        "regex": "(body = <div id=divLogin> | 网御WAF)",
        "type": "bodys",
    },

    "NSFOCUS_WAF": {
        "regex": "(WAF NSFOCUS | body = /images/logo/nsfocus.png)",
        "type": "bodys",
    },

    "斐讯Fortress": {
        "regex": "(斐讯Fortress防火墙 | <meta name=author content=上海斐讯数据通信技术有限公司 />)",
        "type": "bodys",
    },

    "Sophos Web Appliance": {
        "regex": "(Sophos Web Appliance | resources/images/sophos_web.ico | urlresources/images/en/login_swa.jpg)",
        "type": "bodys",
    },

    "Barracuda-Spam-Firewall": {
        "regex": "(Barracuda Spam & Virus Firewall: Welcome | /barracuda.css | http://www.barracudanetworks.com?a=bsf_product)",
        "type": "bodys",
    },

    "DnP-Firewall": {
        "regex": "(Forum Gateway - Powered by DnP Firewall | name=dnp_firewall_redirect |  <form name=dnp_firewall)",
        "type": "bodys",
    },

    "H3C-SecBlade-FireWall": {
        "regex": "(js/MulPlatAPI.js)",
        "type": "bodys",
    },

    "锐捷NBR路由器": {
        "regex": "(free_nbr_login_form.png)",
        "type": "bodys",
    },

    "mikrotik": {
        "regex": "(RouterOS | mikrotik)",
        "type": "bodys",
    },

    "h3c路由器": {
        "regex": "(Web user login | nLanguageSupported)",
        "type": "bodys",
    },

    "jcg无线路由器": {
        "regex": "(Wireless Router | http://www.jcgcn.com)",
        "type": "bodys",
    },

    "Comcast_Business_Gateway": {
        "regex": "(Comcast Business Gateway)",
        "type": "bodys",
    },

    "AirTiesRouter": {
        "regex": "(Airties)",
        "type": "headers",
    },

    "3COM NBX": {
        "regex": "(NBX NetSet | splashTitleIPTelephony)",
        "type": "bodys",
    },

    "H3C ER2100n": {
        "regex": "(ER2100n系统管理)",
        "type": "headers",
    },

    "H3C ICG 1000": {
        "regex": "(ICG 1000系统管理)",
        "type": "headers",
    },

    "H3C AM8000": {
        "regex": "(AM8000)",
        "type": "headers",
    },

    "H3C ER8300G2": {
        "regex": "(ER8300G2系统管理)",
        "type": "headers",
    },

    "H3C ER3108GW": {
        "regex": "(ER3108GW系统管理)",
        "type": "headers",
    },

    "H3C ER6300": {
        "regex": "(ER6300系统管理)",
        "type": "headers",
    },

    "H3C ICG1000": {
        "regex": "(ICG1000系统管理)",
        "type": "headers",
    },

    "H3C ER3260G2": {
        "regex": "(ER3260G2系统管理)",
        "type": "headers",
    },

    "H3C ER3108G": {
        "regex": "(ER3108G系统管理)",
        "type": "headers",
    },

    "H3C ER2100": {
        "regex": "(ER2100系统管理)",
        "type": "headers",
    },

    "H3C ER3200": {
        "regex": "(ER3200系统管理)",
        "type": "headers",
    },

    "H3C ER8300": {
        "regex": "(ER8300系统管理)",
        "type": "headers",
    },

    "H3C ER5200G2": {
        "regex": "(ER5200G2系统管理)",
        "type": "headers",
    },

    "H3C ER6300G2": {
        "regex": "(ER6300G2系统管理)",
        "type": "headers",
    },

    "H3C ER2100V2": {
        "regex": "(ER2100V2系统管理)",
        "type": "headers",
    },

    "H3C ER3260": {
        "regex": "(ER3260系统管理)",
        "type": "headers",
    },

    "H3C ER3100": {
        "regex": "(ER3100系统管理)",
        "type": "headers",
    },

    "H3C ER5100": {
        "regex": "(ER5100系统管理)",
        "type": "headers",
    },

    "H3C ER5200": {
        "regex": "(ER5200系统管理)",
        "type": "headers",
    },

    "UBNT_UniFi系列路由": {
        "regex": "(UniFi | <div class=appGlobalHeader>)",
        "type": "bodys",
    },

    "AnyGate": {
        "regex": "(AnyGate | /anygate.php)",
        "type": "bodys",
    },

    "Astaro-Security-Gateway": {
        "regex": "(wfe/asg/js/app_selector.js?t= | /doc/astaro-license.txt | /js/_variables_from_backend.js?t=)",
        "type": "bodys",
    },

    "Aruba-Device": {
        "regex": "(/images/arubalogo.gif | Aruba Networks)",
        "type": "bodys",
    },

    "AP-Router": {
        "regex": "(AP Router New Generation)",
        "type": "headers",
    },

    "Belkin-Modem": {
        "regex": "(content=Belkin)",
        "type": "bodys",
    },

    "Dell OpenManage Switch Administrator": {
        "regex": "(Dell OpenManage Switch Administrator)",
        "type": "headers",
    },

    "EDIMAX": {
        "regex": "(EDIMAX Technology | content=Edimax)",
        "type": "bodys",
    },

    "eBuilding-Network-Controller": {
        "regex": "(eBuilding Web)",
        "type": "headers",
    },

    "ipTIME-Router": {
        "regex": "(networks - ipTIME | href=iptime.css)",
        "type": "bodys",
    },

    "I-O-DATA-Router": {
        "regex": "(I-O DATA Wireless Broadband Router)",
        "type": "headers",
    },

    "phpshe": {
        "regex": "(Powered by phpshe | content=phpshe)",
        "type": "bodys",
    },

    "ThinkSAAS": {
        "regex": "(/app/home/skins/default/style.css)",
        "type": "bodys",
    },

    "e-tiller": {
        "regex": "(reader/view_abstract.aspx)",
        "type": "bodys",
    },

    "DouPHP": {
        "regex": "(Powered by DouPHP | controlBase | indexLeft | recommendProduct)",
        "type": "bodys",
    },

    "twcms": {
        "regex": "(/twcms/theme/ | /css/global.css)",
        "type": "bodys",
    },

    "SiteServer": {
        "regex": "(http://www.siteserver.cn | SiteServer CMS | Powered by SiteServer CMS | T_系统首页模板 | siteserver | sitefiles)",
        "type": "bodys",
    },

    "Joomla": {
        "regex": "(content=Joomla | /media/system/js/core.js | /media/system/js/mootools-core.js)",
        "type": "bodys",
    },

    "kesionCMS": {
        "regex": "(/ks_inc/common.js | publish by KesionCMS)",
        "type": "bodys",
    },

    "CMSTop": {
        "regex": "(/css/cmstop-common.css | /js/cmstop-common.js | cmstop-list-text.css | <a class=poweredby href=http://www.cmstop.com)",
        "type": "bodys",
    },

    "ESPCMS": {
        "regex": "(Powered by ESPCMS | Powered by ESPCMS | infolist_fff | /templates/default/style/tempates_div.css)",
        "type": "bodys",
    },

    "74cms": {
        "regex": "(content=74cms.com | content=骑士CMS | Powered by <a href=http://www.74cms.com/ | /templates/default/css/common.css | selectjobscategory)",
        "type": "bodys",
    },

    "Foosun": {
        "regex": "(Created by DotNetCMS | For Foosun | Powered by www.Foosun.net,Products:Foosun Content Manage system)",
        "type": "bodys",
    },

    "PhpCMS": {
        "regex": "(http://www.phpcms.cn | content=Phpcms | Powered by Phpcms | data/config.js | /index.php?m=content&c=index&a=lists | /index.php?m=content&amp;c=index&amp;a=lists)",
        "type": "bodys",
    },

    "DedeCMS": {
        "regex": "(Power by DedeCms | http://www.dedecms.com/ | DedeCMS | /templets/default/style/dedecms.css | Powered by DedeCms )",
        "type": "bodys",
    },

    "ASPCMS": {
        "regex": "(Powered by ASPCMS | content=ASPCMS | /inc/AspCms_AdvJs.asp)",
        "type": "bodys",
    },

    "MetInfo": {
        "regex": "(Powered by MetInfo | content=MetInfo | powered_by_metinfo | /images/css/metinfo.css)",
        "type": "bodys",
    },

    "Npoint": {
        "regex": "(Powered by Npoint)",
        "type": "headers",
    },

    "捷点JCMS": {
        "regex": "(Publish By JCms2010)",
        "type": "bodys",
    },

    "帝国EmpireCMS": {
        "regex": "(Powered by EmpireCMS)",
        "type": "headers",
    },

    "JEECMS": {
        "regex": "(Powered by JEECMS | http://www.jeecms.com | JEECMS)",
        "type": "bodys",
    },

    "IdeaCMS": {
        "regex": "(Powered By IdeaCMS | m_ctr32)",
        "type": "bodys",
    },

    "TCCMS": {
        "regex": "(Power By TCCMS | index.php?ac=link_more | index.php?ac=news_list)",
        "type": "bodys",
    },

    "webplus": {
        "regex": "(webplus | 高校网站群管理平台)",
        "type": "bodys",
    },

    "Dolibarr": {
        "regex": "(Dolibarr Development Team)",
        "type": "bodys",
    },

    "Telerik Sitefinity": {
        "regex": "(Telerik.Web.UI.WebResource.axd | content=Sitefinity)",
        "type": "bodys",
    },

    "PageAdmin": {
        "regex": "(content=PageAdmin CMS | /e/images/favicon.ico)",
        "type": "bodys",
    },

    "sdcms": {
        "regex": "(powered by sdcms | var webroot= | /js/sdcms.js)",
        "type": "bodys",
    },

    "EnterCRM": {
        "regex": "(EnterCRM)",
        "type": "bodys",
    },

    "易普拉格科研管理系统": {
        "regex": "(lan12-jingbian-hong | 科研管理系统，北京易普拉格科技)",
        "type": "bodys",
    },

    "苏亚星校园管理系统": {
        "regex": "(/ws2004/Public/)",
        "type": "bodys",
    },

    "trs_wcm": {
        "regex": "(/wcm/app/js | 0;URL=/wcm | window.location.href = /wcm; | forum.trs.com.cn | wcm | /wcm target=_blank>网站管理 | /wcm target=_blank>管理)",
        "type": "bodys",
    },

    "we7": {
        "regex": "(/Widgets/WidgetCollection/)",
        "type": "bodys",
    },

    "1024cms": {
        "regex": "(Powered by 1024 CMS | generator content=1024 CMS c)",
        "type": "bodys",
    },

    "360webfacil_360WebManager": {
        "regex": "(publico/template/ | zonapie | 360WebManager Software)",
        "type": "bodys",
    },

    "6kbbs": {
        "regex": "(Powered by 6kbbs | generator content=6KBBS)",
        "type": "bodys",
    },

    "Acidcat_CMS": {
        "regex": "(Start Acidcat CMS footer information | Powered by Acidcat CMS)",
        "type": "bodys",
    },

    "bit-service": {
        "regex": "(bit-xxzs | xmlpzs/webissue.asp)",
        "type": "bodys",
    },

    "云因网上书店": {
        "regex": "(main/building.cfm | href=../css/newscomm.css)",
        "type": "bodys",
    },

    "MediaWiki": {
        "regex": "(generator content=MediaWiki | /wiki/images/6/64/Favicon.ico | Powered by MediaWiki)",
        "type": "bodys",
    },

    "Typecho": {
        "regex": "(generator content=Typecho | 强力驱动 | Typecho)",
        "type": "bodys",
    },

    "2z project": {
        "regex": "(Generator content=2z project)",
        "type": "bodys",
    },

    "phpDocumentor": {
        "regex": "(Generated by phpDocumentor)",
        "type": "bodys",
    },

    "微门户": {
        "regex": "(/tpl/Home/weimeng/common/css/)",
        "type": "bodys",
    },

    "webEdition": {
        "regex": "(generator content=webEdition)",
        "type": "bodys",
    },

    "orocrm": {
        "regex": "(/bundles/oroui/)",
        "type": "bodys",
    },

    "创星伟业校园网群": {
        "regex": "(javascripts/float.js | vcxvcxv)",
        "type": "bodys",
    },

    "BoyowCMS": {
        "regex": "(publish by BoyowCMS)",
        "type": "bodys",
    },

    "正方教务管理系统": {
        "regex": "(style/base/jw.css)",
        "type": "bodys",
    },

    "UFIDA_NC": {
        "regex": "(UFIDA | logo/images/ | logo/images/ufida_nc.png)",
        "type": "bodys",
    },

    "phpweb": {
        "regex": "(PDV_PAGENAME)",
        "type": "bodys",
    },

    "地平线CMS": {
        "regex": "(labelOppInforStyle | Powered by deep soon | search_result.aspx | frmsearch)",
        "type": "bodys",
    },

    "HIMS酒店云计算服务": {
        "regex": "(GB_ROOT_DIR | maincontent.css | HIMS酒店云计算服务)",
        "type": "bodys",
    },

    "Tipask": {
        "regex": "(content=tipask)",
        "type": "bodys",
    },

    "北创图书检索系统": {
        "regex": "(opac_two)",
        "type": "bodys",
    },

    "微普外卖点餐系统": {
        "regex": "(Author content=微普外卖点餐系统 | Powered By 点餐系统 | userfiles/shoppics/)",
        "type": "bodys",
    },

    "逐浪zoomla": {
        "regex": "(script src=http://code.zoomla.cn/ | NodePage.aspx | Item | /style/images/win8_symbol_140x140.png)",
        "type": "bodys",
    },

    "北京清科锐华CEMIS": {
        "regex": "(/theme/2009/image | login.asp)",
        "type": "bodys",
    },

    "asp168欧虎": {
        "regex": "(upload/moban/images/style.css | default.php?mod=article&do=detail&tid)",
        "type": "bodys",
    },

    "擎天电子政务": {
        "regex": "(App_Themes/1/Style.css | window.location = homepages/index.aspx | homepages/content_page.aspx)",
        "type": "bodys",
    },

    "北京阳光环球建站系统": {
        "regex": "(bigSortProduct.asp?bigid)",
        "type": "bodys",
    },

    "MaticsoftSNS_动软分享社区": {
        "regex": "(MaticsoftSNS | maticsoft | /Areas/SNS/)",
        "type": "bodys",
    },

    "FineCMS": {
        "regex": "(Powered by FineCMS | dayrui@gmail.com | Copyright content=FineCMS)",
        "type": "bodys",
    },

    "Diferior": {
        "regex": "(Powered by Diferior)",
        "type": "bodys",
    },

    "国家数字化学习资源中心系统": {
        "regex": "(页面加载中,请稍候 | FrontEnd)",
        "type": "bodys",
    },

    "某通用型政府cms": {
        "regex": "(/deptWebsiteAction.do)",
        "type": "bodys",
    },

    "万户网络": {
        "regex": "(css/css_whir.css)",
        "type": "bodys",
    },

    "rcms": {
        "regex": "(/r/cms/www/ | jhtml)",
        "type": "bodys",
    },

    "全国烟草系统": {
        "regex": "(ycportal/webpublish)",
        "type": "bodys",
    },

    "O2OCMS": {
        "regex": "(/index.php/clasify/showone/gtitle/)",
        "type": "bodys",
    },

    "一采通": {
        "regex": "(/custom/GroupNewsList.aspx?GroupId=)",
        "type": "bodys",
    },

    "Dolphin": {
        "regex": "(bx_css_async)",
        "type": "bodys",
    },

    "wecenter": {
        "regex": "(aw_template.js | WeCenter)",
        "type": "bodys",
    },

    "phpvod": {
        "regex": "(Powered by PHPVOD | content=phpvod)",
        "type": "bodys",
    },

    "08cms": {
        "regex": "(content=08CMS | typeof_08cms)",
        "type": "bodys",
    },

    "tutucms": {
        "regex": "(content=TUTUCMS | Powered by TUTUCMS | TUTUCMS)",
        "type": "bodys",
    },

    "八哥CMS": {
        "regex": "(content=BageCMS)",
        "type": "bodys",
    },

    "mymps": {
        "regex": "(/css/mymps.css | mymps | content=mymps)",
        "type": "bodys",
    },

    "IMGCms": {
        "regex": "(content=IMGCMS | Powered by IMGCMS)",
        "type": "bodys",
    },

    "jieqi cms": {
        "regex": "(content=jieqi cms | jieqi cms)",
        "type": "bodys",
    },

    "eadmin": {
        "regex": "(content=eAdmin | eadmin)",
        "type": "bodys",
    },

    "opencms": {
        "regex": "(content=OpenCms | Powered by OpenCms)",
        "type": "bodys",
    },

    "infoglue": {
        "regex": "(infoglue | infoglueBox.png)",
        "type": "bodys",
    },

    "171cms": {
        "regex": "(content=171cms | 171cms)",
        "type": "bodys",
    },

    "doccms": {
        "regex": "(Power by DocCms)",
        "type": "bodys",
    },

    "appcms": {
        "regex": "(Powerd by AppCMS)",
        "type": "bodys",
    },

    "niucms": {
        "regex": "(content=NIUCMS)",
        "type": "bodys",
    },

    "baocms": {
        "regex": "(content=BAOCMS | baocms)",
        "type": "bodys",
    },

    "PublicCMS": {
        "regex": "(publiccms)",
        "type": "headers",
    },

    "JTBC(CMS)": {
        "regex": "(/js/jtbc.js | content=JTBC)",
        "type": "bodys",
    },

    "易企CMS": {
        "regex": "(content=YiqiCMS)",
        "type": "bodys",
    },

    "ZCMS": {
        "regex": "(_ZCMS_ShowNewMessage | zcms_skin | ZCMS泽元内容管理)",
        "type": "bodys",
    },

    "科蚁CMS": {
        "regex": "(keyicms：keyicms | Powered by <a href=http://www.keyicms.com)",
        "type": "bodys",
    },

    "苹果CMS": {
        "regex": "(maccms:voddaycount)",
        "type": "bodys",
    },

    "大米CMS": {
        "regex": "(大米CMS- | content=damicms | content=大米CMS)",
        "type": "bodys",
    },

    "phpmps": {
        "regex": "(Powered by Phpmps | templates/phpmps/style/index.css)",
        "type": "bodys",
    },

    "25yi": {
        "regex": "(Powered by 25yi | css/25yi.css)",
        "type": "bodys",
    },

    "kingcms": {
        "regex": "(kingcms | content=KingCMS | Powered by KingCMS)",
        "type": "bodys",
    },

    "易点CMS": {
        "regex": "(DianCMS_SiteName | DianCMS_用户登陆引用)",
        "type": "bodys",
    },

    "fengcms": {
        "regex": "(Powered by FengCms | content=FengCms)",
        "type": "bodys",
    },

    "phpb2b": {
        "regex": "(Powered By PHPB2B)",
        "type": "bodys",
    },

    "phpdisk": {
        "regex": "(Powered by PHPDisk | content=PHPDisk)",
        "type": "bodys",
    },

    "EduSoho开源网络课堂": {
        "regex": "(edusoho | Powered by <a href=http://www.edusoho.com | Powered By EduSoho)",
        "type": "bodys",
    },

    "phpok": {
        "regex": "(phpok | Powered By phpok.com | content=phpok)",
        "type": "bodys",
    },

    "dtcms": {
        "regex": "(dtcms | content=动力启航,DTCMS)",
        "type": "bodys",
    },

    "beecms": {
        "regex": "(powerd by | BEESCMS | template/default/images/slides.min.jquery.js)",
        "type": "bodys",
    },

    "ourphp": {
        "regex": "(content=OURPHP | Powered by ourphp)",
        "type": "bodys",
    },

    "php云": {
        "regex": "(<div class=index_link_list_name>)",
        "type": "bodys",
    },

    "贷齐乐p2p": {
        "regex": "(/js/jPackageCss/jPackage.css | src=/js/jPackage)",
        "type": "bodys",
    },

    "中企动力门户CMS": {
        "regex": "(中企动力提供技术支持)",
        "type": "bodys",
    },

    "destoon": {
        "regex": "(<meta name=generator content=Destoon | destoon_moduleid)",
        "type": "bodys",
    },

    "帝友P2P": {
        "regex": "(/js/diyou.js | src=/dyweb/dythemes)",
        "type": "bodys",
    },

    "海洋CMS": {
        "regex": "(seacms | Powered by SeaCms | content=seacms)",
        "type": "bodys",
    },

    "合正网站群内容管理系统": {
        "regex": "(Produced By | 网站群内容管理系统)",
        "type": "bodys",
    },

    "OpenSNS": {
        "regex": "(opensns | content=OpenSNS)",
        "type": "bodys",
    },

    "SEMcms": {
        "regex": "(semcms PHP | sc_mid_c_left_c sc_mid_left_bt)",
        "type": "bodys",
    },

    "Yxcms": {
        "regex": "(/css/yxcms.css | content=Yxcms)",
        "type": "bodys",
    },

    "NITC": {
        "regex": "(NITC Web Marketing Service | /images/nitc1.png)",
        "type": "bodys",
    },

    "wuzhicms": {
        "regex": "(Powered by wuzhicms | content=wuzhicms)",
        "type": "bodys",
    },

    "PHPMyWind": {
        "regex": "(phpMyWind.com All Rights Reserved | content=PHPMyWind)",
        "type": "bodys",
    },

    "SiteEngine": {
        "regex": "(content=Boka SiteEngine)",
        "type": "bodys",
    },

    "b2bbuilder": {
        "regex": "(content=B2Bbuilder | translateButtonId = B2Bbuilder)",
        "type": "bodys",
    },

    "农友政务系统": {
        "regex": "(1207044504)",
        "type": "bodys",
    },

    "dswjcms": {
        "regex": "(content=Dswjcms | Powered by Dswjcms)",
        "type": "bodys",
    },

    "FoxPHP": {
        "regex": "(FoxPHPScroll | FoxPHP_ImList | content=FoxPHP)",
        "type": "bodys",
    },

    "weiphp": {
        "regex": "(content=WeiPHP | /css/weiphp.css)",
        "type": "bodys",
    },

    "iWebSNS": {
        "regex": "(/jooyea/images/sns_idea1.jpg | /jooyea/images/snslogo.gif)",
        "type": "bodys",
    },

    "TurboCMS": {
        "regex": "(Powered by TurboCMS |  /cmsapp/zxdcADD.jsp | /cmsapp/count/newstop_index.jsp?siteid=)",
        "type": "bodys",
    },

    "MoMoCMS": {
        "regex": "(content=MoMoCMS | Powered BY MoMoCMS)",
        "type": "bodys",
    },

    "Acidcat CMS": {
        "regex": "(Powered by Acidcat CMS | Start Acidcat CMS footer information | /css/admin_import.css)",
        "type": "bodys",
    },

    "WP Plugin All-in-one-SEO-Pack": {
        "regex": "(<!-- /all in one seo pack -->)",
        "type": "bodys",
    },

    "Aardvark Topsites": {
        "regex": "(Aardvark Topsites)",
        "type": "bodys",
    },

    "1024 CMS": {
        "regex": "(Powered by 1024 CMS | content=1024 CMS)",
        "type": "bodys",
    },

    "68 Classifieds": {
        "regex": "(68 Classifieds)",
        "type": "bodys",
    },

    "武汉弘智科技": {
        "regex": "(武汉弘智科技有限公司)",
        "type": "bodys",
    },

    "北京金盘鹏图软件": {
        "regex": "(SpeakIntertScarch.aspx)",
        "type": "bodys",
    },

    "育友软件": {
        "regex": "(http://www.yuysoft.com/)",
        "type": "bodys",
    },

    "STcms": {
        "regex": "(content=STCMS | DahongY<dahongy@gmail.com>)",
        "type": "bodys",
    },

    "青果软件": {
        "regex": "(KINGOSOFT | SetKingoEncypt.jsp | /jkingo.js)",
        "type": "bodys",
    },

    "DirCMS": {
        "regex": "(content=DirCMS)",
        "type": "bodys",
    },

    "牛逼cms": {
        "regex": "(content=niubicms)",
        "type": "bodys",
    },

    "南方数据": {
        "regex": "(/SouthidcKeFu.js | CONTENT=Copyright 2003-2015 - Southidc.net | /Southidcj2f.Js)",
        "type": "bodys",
    },

    "yidacms": {
        "regex": "(yidacms.css)",
        "type": "bodys",
    },

    "bluecms": {
        "regex": "(power by bcms | bcms_plugin)",
        "type": "bodys",
    },

    "taocms": {
        "regex": "(>taoCMS<)",
        "type": "bodys",
    },

    "Tiki-wiki CMS": {
        "regex": "(jqueryTiki = new Object)",
        "type": "bodys",
    },

    "lepton-cms": {
        "regex": "(content=LEPTON-CMS | Powered by LEPTON CMS)",
        "type": "bodys",
    },

    "euse_study": {
        "regex": "(UserInfo/UserFP.aspx)",
        "type": "bodys",
    },

    "沃科网异网同显系统": {
        "regex": "(沃科网 | 异网同显系统)",
        "type": "bodys",
    },

    "Mixcall座席管理中心": {
        "regex": "(Mixcall座席管理中心)",
        "type": "headers",
    },

    "DuomiCms": {
        "regex": "(DuomiCms | Power by DuomiCms)",
        "type": "bodys",
    },

    "ANECMS": {
        "regex": "(content=Erwin Aligam - ealigam@gmail.com)",
        "type": "bodys",
    },

    "Ananyoo-CMS": {
        "regex": "(content=http://www.ananyoo.com)",
        "type": "bodys",
    },

    "Amiro-CMS": {
        "regex": "(Powered by: Amiro CMS | -= Amiro.CMS c =-)",
        "type": "bodys",
    },

    "AlumniServer": {
        "regex": "(AlumniServerProject.php | content=Alumni)",
        "type": "bodys",
    },

    "AlstraSoft-EPay-Enterprise": {
        "regex": "(Powered by EPay Enterprise | /shop.htm?action=view)",
        "type": "bodys",
    },

    "AlstraSoft-AskMe": {
        "regex": "(<a href=pass_recover.php> | http://www.alstrasoft.com)",
        "type": "bodys",
    },

    "Artiphp-CMS": {
        "regex": "(copyright Artiphp)",
        "type": "bodys",
    },

    "BIGACE": {
        "regex": "(content=BIGACE | Site is running BIGACE)",
        "type": "bodys",
    },

    "Biromsoft-WebCam": {
        "regex": "(Biromsoft WebCam)",
        "type": "headers",
    },

    "BackBee": {
        "regex": "(<div id=bb5-site-wrapper>)",
        "type": "bodys",
    },

    "Auto-CMS": {
        "regex": "(Powered by Auto CMS | content=AutoCMS)",
        "type": "bodys",
    },

    "STAR CMS": {
        "regex": "(content=STARCMS | <img alt=STAR CMS)",
        "type": "bodys",
    },

    "Zotonic": {
        "regex": "(powered by: Zotonic | /lib/js/apps/zotonic-1.0)",
        "type": "bodys",
    },

    "BloofoxCMS": {
        "regex": "(content=bloofoxCMS | Powered by <a href=http://www.bloofox.com)",
        "type": "bodys",
    },

    "BlognPlus": {
        "regex": "(href=http://www.blogn.org)",
        "type": "bodys",
    },

    "bitweaver": {
        "regex": "(content=bitweaver | href=http://www.bitweaver.org>Powered by)",
        "type": "bodys",
    },

    "ClanSphere": {
        "regex": "(content=ClanSphere | index.php?mod=clansphere&amp;action=about)",
        "type": "bodys",
    },

    "CitusCMS": {
        "regex": "(Powered by CitusCMS | <strong>CitusCMS</strong> | content=CitusCMS)",
        "type": "bodys",
    },

    "CMS-WebManager-Pro": {
        "regex": "(content=Webmanager-pro | href=http://webmanager-pro.com>Web.Manager)",
        "type": "bodys",
    },

    "CMSQLite": {
        "regex": "(powered by CMSQLite | content=www.CMSQLite.net)",
        "type": "bodys",
    },

    "CMSimple": {
        "regex": "(Powered by CMSimple.dk | content=CMSimple)",
        "type": "bodys",
    },

    "CMScontrol": {
        "regex": "(content=CMScontrol)",
        "type": "bodys",
    },

    "Claroline": {
        "regex": "(target=_blank>Claroline</a> | http://www.claroline.net rel=Copyright)",
        "type": "bodys",
    },

    "Car-Portal": {
        "regex": "(Powered by <a href=http://www.netartmedia.net/carsportal | class=bodyfontwhite><strong>&nbsp;Car Script)",
        "type": "bodys",
    },

    "chillyCMS": {
        "regex": "(powered by <a href=http://FrozenPepper.de)",
        "type": "bodys",
    },

    "BoonEx-Dolphin": {
        "regex": "(Powered by Dolphin)",
        "type": "bodys",
    },

    "SilverStripe": {
        "regex": "(content=SilverStripe)",
        "type": "bodys",
    },

    "Campsite": {
        "regex": "(content=Campsite)",
        "type": "bodys",
    },

    "ischoolsite": {
        "regex": "(Powered by <a href=http://www.ischoolsite.com)",
        "type": "bodys",
    },

    "CafeEngine": {
        "regex": "(/CafeEngine/style.css | <a href=http://cafeengine.com>CafeEngine.com)",
        "type": "bodys",
    },

    "BrowserCMS": {
        "regex": "(Powered by BrowserCMS | content=BrowserCMS)",
        "type": "bodys",
    },

    "Contrexx-CMS": {
        "regex": "(powered by Contrexx | content=Contrexx)",
        "type": "bodys",
    },

    "ContentXXL": {
        "regex": "(content=contentXXL)",
        "type": "bodys",
    },

    "Contentteller-CMS": {
        "regex": "(content=Esselbach Contentteller CMS)",
        "type": "bodys",
    },

    "Contao": {
        "regex": "(system/contao.css)",
        "type": "bodys",
    },

    "CommonSpot": {
        "regex": "(content=CommonSpot)",
        "type": "bodys",
    },

    "CruxCMS": {
        "regex": "(Created by CruxCMS | CruxCMS class=blank)",
        "type": "bodys",
    },

    "锐商企业CMS": {
        "regex": "(href=/Writable/ClientImages/mycss.css)",
        "type": "bodys",
    },

    "coWiki": {
        "regex": "(content=coWiki | <!-- Generated by coWiki)",
        "type": "bodys",
    },

    "Coppermine": {
        "regex": "(<!--Coppermine Photo Gallery)",
        "type": "bodys",
    },

    "DaDaBIK": {
        "regex": "(content=DaDaBIK | class=powered_by_dadabik)",
        "type": "bodys",
    },

    "Custom-CMS": {
        "regex": "(content=CustomCMS | Powered by CCMS)",
        "type": "bodys",
    },

    "DT-Centrepiece": {
        "regex": "(content=DT Centrepiece | Powered By DT Centrepiece)",
        "type": "bodys",
    },

    "Edito-CMS": {
        "regex": "(content=edito | CMS href=http://www.edito.pl/)",
        "type": "bodys",
    },

    "Echo": {
        "regex": "(powered by echo | /Echo2/echoweb/login)",
        "type": "bodys",
    },

    "Ecomat-CMS": {
        "regex": "(content=ECOMAT CMS)",
        "type": "bodys",
    },

    "EazyCMS": {
        "regex": "(powered by eazyCMS | <a class=actionlink href=http://www.eazyCMS.com)",
        "type": "bodys",
    },

    "easyLink-Web-Solutions": {
        "regex": "(content=easyLink)",
        "type": "bodys",
    },

    "EasyConsole-CMS": {
        "regex": "(Powered by EasyConsole CMS | Powered by <a href=http://www.easyconsole.com)",
        "type": "bodys",
    },

    "DotCMS": {
        "regex": "(/dotAsset/ | /index.dot)",
        "type": "bodys",
    },

    "DBHcms": {
        "regex": "(powered by DBHcms)",
        "type": "bodys",
    },

    "Donations-Cloud": {
        "regex": "(/donationscloud.css)",
        "type": "bodys",
    },

    "Dokeos": {
        "regex": "(href=http://www.dokeos.com rel=Copyright | content=Dokeos | name=Generator content=Dokeos)",
        "type": "bodys",
    },

    "Elxis-CMS": {
        "regex": "(content=Elxis)",
        "type": "bodys",
    },

    "eFront": {
        "regex": "(<a href = http://www.efrontlearning.net)",
        "type": "bodys",
    },

    "eSitesBuilder": {
        "regex": "(eSitesBuilder. All rights reserved)",
        "type": "bodys",
    },

    "EPiServer": {
        "regex": "(content=EPiServer | /javascript/episerverscriptmanager.js)",
        "type": "bodys",
    },

    "Energine": {
        "regex": "(scripts/Energine.js | Powered by <a href= http://energine.org/ | stylesheets/energine.css)",
        "type": "bodys",
    },

    "Gallery": {
        "regex": "(Gallery 3 Installer | /gallery/images/gallery.png)",
        "type": "bodys",
    },

    "FrogCMS": {
        "regex": "(target=_blank>Frog CMS | href=http://www.madebyfrog.com>Frog CMS)",
        "type": "bodys",
    },

    "Fossil": {
        "regex": "(<a href=http://fossil-scm.org)",
        "type": "bodys",
    },

    "FCMS": {
        "regex": "(content=Ryan Haudenschilt | Powered by Family Connections)",
        "type": "bodys",
    },

    "Fastpublish-CMS": {
        "regex": "(content=fastpublish)",
        "type": "bodys",
    },

    "F3Site": {
        "regex": "(Powered by <a href=http://compmaster.prv.pl)",
        "type": "bodys",
    },

    "Exponent-CMS": {
        "regex": "(content=Exponent Content Management System | Powered by Exponent CMS)",
        "type": "bodys",
    },

    "E-Xoopport": {
        "regex": "(Powered by E-Xoopport | content=E-Xoopport)",
        "type": "bodys",
    },

    "E-Manage-MySchool": {
        "regex": "(E-Manage All Rights Reserved MySchool Version)",
        "type": "bodys",
    },

    "glFusion": {
        "regex": "(by <a href=http://www.glfusion.org/)",
        "type": "bodys",
    },

    "GetSimple": {
        "regex": "(content=GetSimple | Powered by GetSimple)",
        "type": "bodys",
    },

    "HESK": {
        "regex": "(hesk_javascript.js | hesk_style.css | Powered by <a href=http://www.hesk.com | Powered by <a href=https://www.hesk.com)",
        "type": "bodys",
    },

    "GuppY": {
        "regex": "(content=GuppY | class=copyright href=http://www.freeguppy.org/)",
        "type": "bodys",
    },

    "FluentNET": {
        "regex": "(content=Fluent)",
        "type": "bodys",
    },

    "GeekLog": {
        "regex": "(Powered By <a href=http://www.geeklog.net/)",
        "type": "bodys",
    },

    "Hycus-CMS": {
        "regex": "(content=Hycus | Powered By <a href=http://www.hycus.com)",
        "type": "bodys",
    },

    "Hotaru-CMS": {
        "regex": "(content=Hotaru)",
        "type": "bodys",
    },

    "HoloCMS": {
        "regex": "(Powered by HoloCMS)",
        "type": "bodys",
    },

    "ImpressPages-CMS": {
        "regex": "(content=ImpressPages CMS)",
        "type": "bodys",
    },

    "iGaming-CMS": {
        "regex": "(http://www.igamingcms.com/)",
        "type": "bodys",
    },

    "xoops": {
        "regex": "(include/xoops.js)",
        "type": "bodys",
    },

    "Intraxxion-CMS": {
        "regex": "(content=Intraxxion | <!-- site built by Intraxxion)",
        "type": "bodys",
    },

    "InterRed": {
        "regex": "(content=InterRed | Created with InterRed)",
        "type": "bodys",
    },

    "Informatics-CMS": {
        "regex": "(content=Informatics)",
        "type": "bodys",
    },

    "JagoanStore": {
        "regex": "(href=http://www.jagoanstore.com/ target=_blank>Toko Online)",
        "type": "bodys",
    },

    "Kandidat-CMS": {
        "regex": "(content=Kandidat-CMS)",
        "type": "bodys",
    },

    "Kajona": {
        "regex": "(content=Kajona | powered by Kajona)",
        "type": "bodys",
    },

    "JGS-Portal": {
        "regex": "(Powered by <b>JGS-Portal Version | href=jgs_portal_box.php?id=)",
        "type": "bodys",
    },

    "jCore": {
        "regex": "(JCORE_VERSION = )",
        "type": "bodys",
    },

    "EdmWebVideo": {
        "regex": "(EdmWebVideo)",
        "type": "headers",
    },

    "edvr": {
        "regex": "(edvs/edvr)",
        "type": "headers",
    },

    "Polycom": {
        "regex": "(Polycom | kAllowDirectHTMLFileAccess)",
        "type": "bodys",
    },

    "techbridge": {
        "regex": "(Sorry,you need to use IE brower)",
        "type": "bodys",
    },

    "NETSurveillance": {
        "regex": "(NETSurveillance)",
        "type": "headers",
    },

    "nvdvr": {
        "regex": "(XWebPlay)",
        "type": "headers",
    },

    "DVR camera": {
        "regex": "(DVR WebClient)",
        "type": "headers",
    },

    "Macrec_DVR": {
        "regex": "(Macrec DVR)",
        "type": "headers",
    },

    "OnSSI_Video_Clients": {
        "regex": "(OnSSI Video Clients | x-value=On-Net Surveillance Systems Inc.)",
        "type": "bodys",
    },

    "Linksys_SPA_Configuration ": {
        "regex": "(Linksys SPA Configuration)",
        "type": "headers",
    },

    "eagleeyescctv": {
        "regex": "(IP Surveillance for Your Life | /nobody/loginDevice.js)",
        "type": "bodys",
    },

    "dasannetworks": {
        "regex": "(clear_cookielogin;)",
        "type": "bodys",
    },

    "海康威视iVMS": {
        "regex": "(g_szCacheTime | iVMS)",
        "type": "bodys",
    },

    "佳能网络摄像头(Canon Network Cameras)": {
        "regex": "(/viewer/live/en/live.html)",
        "type": "bodys",
    },

    "NetDvrV3": {
        "regex": "(objLvrForNoIE)",
        "type": "bodys",
    },

    "SIEMENS IP Cameras": {
        "regex": "(SIEMENS IP Camera)",
        "type": "headers",
    },

    "VideoIQ Camera": {
        "regex": "(VideoIQ Camera Login)",
        "type": "headers",
    },

    "Honeywell IP-Camera": {
        "regex": "(Honeywell IP-Camera)",
        "type": "headers",
    },

    "sony摄像头": {
        "regex": "(Sony Network Camera | inquiry.cgi?inqjs=system&inqjs=camera)",
        "type": "bodys",
    },

    "AJA-Video-Converter": {
        "regex": "(eParamID_SWVersion)",
        "type": "bodys",
    },

    "ACTi": {
        "regex": "(Web Configurator | ACTi Corporation All Rights Reserved)",
        "type": "bodys",
    },

    "Samsung DVR": {
        "regex": "(Samsung DVR)",
        "type": "headers",
    },

    "Vicworl": {
        "regex": "(Powered by Vicworl | content=Vicworl | vindex_right_d)",
        "type": "bodys",
    },

    "AVCON6": {
        "regex": "(filename=AVCON6Setup.exe | AVCON6系统管理平台  | language_dispose.action)",
        "type": "bodys",
    },

    "Axis-Network-Camera": {
        "regex": "(AXIS Video Server | /incl/trash.shtml)",
        "type": "bodys",
    },

    "Panasonic Network Camera": {
        "regex": "(MultiCameraFrame?Mode=Motion&Language)",
        "type": "bodys",
    },

    "BlueNet-Video": {
        "regex": "(/cgi-bin/client_execute.cgi?tUD=0 | BlueNet Video Viewer Version)",
        "type": "bodys",
    },

    "ClipBucket": {
        "regex": "(content=ClipBucket | <!-- ClipBucket | <!-- Forged by ClipBucket | href=http://clip-bucket.com/>ClipBucket)",
        "type": "bodys",
    },

    "ZoneMinder": {
        "regex": "(ZoneMinder Login)",
        "type": "bodys",
    },

    "DVR-WebClient": {
        "regex": "(259F9FDF-97EA-4C59-B957-5160CAB6884E | DVR-WebClient)",
        "type": "bodys",
    },

    "D-Link-Network-Camera": {
        "regex": "(DCS-950G.toLowerCase | DCS-5300)",
        "type": "bodys",
    },

    "DiBos": {
        "regex": "(DiBos - Login | style/bovisnt.css)",
        "type": "bodys",
    },

    "Evo-Cam": {
        "regex": "(value=evocam.jar | <applet archive=evocam.jar)",
        "type": "bodys",
    },

    "Intellinet-IP-Camera": {
        "regex": "(Copyright &copy;  INTELLINET NETWORK SOLUTIONS | http://www.intellinet-network.com/driver/NetCam.exe)",
        "type": "bodys",
    },

    "IQeye-Netcam": {
        "regex": "(IQEYE: Live Images | content=Brian Lau, IQinVision | loc = iqeyevid.html)",
        "type": "bodys",
    },

    "phpwind": {
        "regex": "(Powered by phpwind | content=phpwind)",
        "type": "bodys",
    },

    "discuz": {
        "regex": "(Powered by Discuz | content=Discuz | discuz_uid | portal.php?mod=view | Powered by <strong><a href=http://www.discuz.net)",
        "type": "bodys",
    },

    "6kbbs": {
        "regex": "(Powered by 6kbbs | generator content=6KBBS)",
        "type": "bodys",
    },

    "IP.Board": {
        "regex": "(ipb.vars)",
        "type": "bodys",
    },

    "ThinkOX": {
        "regex": "(Powered By ThinkOX | ThinkOX)",
        "type": "bodys",
    },

    "bbPress": {
        "regex": "(<!-- If you like showing off the fact that your server rocks --> | is proudly powered by <a href=http://bbpress.org)",
        "type": "bodys",
    },

    "BlogEngine_NET": {
        "regex": "(pics/blogengine.ico | http://www.dotnetblogengine.net)",
        "type": "bodys",
    },

    "boastMachine": {
        "regex": "(powered by boastMachine | Powered by <a href=http://boastology.com)",
        "type": "bodys",
    },

    "BrewBlogger": {
        "regex": "(developed by <a href=http://www.zkdigital.com)",
        "type": "bodys",
    },

    "Dotclear": {
        "regex": "(Powered by <a href=http://dotclear.org/)",
        "type": "bodys",
    },

    "DokuWiki": {
        "regex": "(powered by DokuWiki | content=DokuWiki | <div id=dokuwiki)",
        "type": "bodys",
    },

    "DeluxeBB": {
        "regex": "(content=powered by DeluxeBB)",
        "type": "bodys",
    },

    "esoTalk": {
        "regex": "(generated by esoTalk | Powered by esoTalk | /js/esotalk.js)",
        "type": "bodys",
    },

    "Hiki": {
        "regex": "(content=Hiki | /hiki_base.css | by <a href=http://hikiwiki.org/)",
        "type": "bodys",
    },

    "Gossamer-Forum": {
        "regex": "(href=gforum.cgi?username= | Gossamer Forum)",
        "type": "bodys",
    },

    "Forest-Blog": {
        "regex": "(Forest Blog)",
        "type": "headers",
    },

    "FluxBB": {
        "regex": "(Powered by <a href=http://fluxbb.org/)",
        "type": "bodys",
    },

    "Kampyle": {
        "regex": "(http://cf.kampyle.com/k_button.js | Start Kampyle Feedback Form Button)",
        "type": "bodys",
    },

    "KaiBB": {
        "regex": "(Powered by KaiBB | content=Forum powered by KaiBB)",
        "type": "bodys",
    },

    "fangmail": {
        "regex": "(/fangmail/default/css/em_css.css)",
        "type": "bodys",
    },

    "MDaemon": {
        "regex": "(/WorldClient.dll?View=Main)",
        "type": "bodys",
    },

    "网易企业邮箱": {
        "regex": "(frmvalidator | 邮箱用户登录)",
        "type": "bodys",
    },

    "TurboMail": {
        "regex": "(Powered by TurboMail | wzcon1 clearfix | TurboMail邮件系统)",
        "type": "bodys",
    },

    "万网企业云邮箱": {
        "regex": "(static.mxhichina.com/images/favicon.ico)",
        "type": "bodys",
    },

    "bxemail": {
        "regex": "(百讯安全邮件系统 | 百姓邮局 | 请输入正确的电子邮件地址，如：abc@bxemail.com)",
        "type": "bodys",
    },

    "Coremail": {
        "regex": "(/coremail/common/assets | Coremail邮件系统)",
        "type": "headers",
    },

    "Lotus": {
        "regex": "(IBM Lotus iNotes Login | iwaredir.nsf)",
        "type": "bodys",
    },

    "mirapoint": {
        "regex": "(/wm/mail/login.html)",
        "type": "bodys",
    },

    "U-Mail": {
        "regex": "(<BODY LINK=White VLINK=White ALINK=White>)",
        "type": "bodys",
    },

    "Spammark邮件信息安全网关": {
        "regex": "(Spammark邮件信息安全网关 | /cgi-bin/spammark?empty=1)",
        "type": "bodys",
    },

    "科信邮件系统": {
        "regex": "(/systemfunction.pack.js | lo_computername)",
        "type": "bodys",
    },

    "winwebmail": {
        "regex": "(winwebmail | WinWebMail Server  | images/owin.css)",
        "type": "bodys",
    },

    "泰信TMailer邮件系统": {
        "regex": "(Tmailer | content=Tmailer | href=/tmailer/img/logo/favicon.ico)",
        "type": "bodys",
    },

    "richmail": {
        "regex": "(Richmail | /resource/se/lang/se/mail_zh_CN.js | content=Richmail)",
        "type": "bodys",
    },

    "iGENUS邮件系统": {
        "regex": "(Copyright by<A HREF=http://www.igenus.org | iGENUS webmail)",
        "type": "bodys",
    },

    "金笛邮件系统": {
        "regex": "(/jdwm/cgi/login.cgi?login)",
        "type": "bodys",
    },

    "迈捷邮件系统(MagicMail)": {
        "regex": "(/aboutus/magicmail.gif)",
        "type": "bodys",
    },

    "Atmail-WebMail": {
        "regex": "(Powered by Atmail | /index.php/mail/auth/processlogin | <input id=Mailserverinput)",
        "type": "bodys",
    },

    "FormMail": {
        "regex": "(/FormMail.pl | href=http://www.worldwidemart.com/scripts/formmail.shtml)",
        "type": "bodys",
    },

    "同城多用户商城": {
        "regex": "(style_chaoshi)",
        "type": "bodys",
    },

    "iWebShop": {
        "regex": "(/runtime/default/systemjs)",
        "type": "bodys",
    },

    "1und1": {
        "regex": "(/shop/catalog/browse?sessid=)",
        "type": "bodys",
    },

    "cart_engine": {
        "regex": "(skins/_common/jscripts.css)",
        "type": "bodys",
    },

    "Magento": {
        "regex": "(/skin/frontend/ | BLANK_IMG | Magento, Varien, E-commerce)",
        "type": "bodys",
    },

    "OpenCart": {
        "regex": "(Powered By OpenCart | catalog/view/theme)",
        "type": "bodys",
    },

    "hishop": {
        "regex": "(hishop.plugins.openid | Hishop development team)",
        "type": "bodys",
    },

    "Maticsoft_Shop_动软商城": {
        "regex": "(Maticsoft Shop | maticsoft | /Areas/Shop/)",
        "type": "bodys",
    },

    "hikashop": {
        "regex": "(/media/com_hikashop/css/)",
        "type": "bodys",
    },

    "tp-shop": {
        "regex": "(mn-c-top)",
        "type": "bodys",
    },

    " 海盗云商(Haidao)": {
        "regex": "(haidao.web.general.js)",
        "type": "bodys",
    },

    "shopbuilder": {
        "regex": "(content=ShopBuilder | Powered by ShopBuilder | ShopBuilder版权所有)",
        "type": "bodys",
    },

    "v5shop": {
        "regex": "(v5shop | content=V5shop | Powered by V5Shop)",
        "type": "bodys",
    },

    "shopnc": {
        "regex": "(Powered by ShopNC | Copyright 2007-2014 ShopNC Inc | content=ShopNC)",
        "type": "bodys",
    },

    "shopex": {
        "regex": "(content=ShopEx | @author litie[aita]shopex.cn)",
        "type": "bodys",
    },

    "dbshop": {
        "regex": "(content=dbshop)",
        "type": "bodys",
    },

    "任我行电商": {
        "regex": "(content=366EC)",
        "type": "bodys",
    },

    "CuuMall": {
        "regex": "(Power by CuuMall)",
        "type": "bodys",
    },

    "javashop": {
        "regex": "(易族智汇javashop | javashop微信公众号 | content=JavaShop)",
        "type": "bodys",
    },

    "TPshop": {
        "regex": "(/index.php/Mobile/Index/index.html | >TPshop开源商城<)",
        "type": "bodys",
    },

    "MvMmall": {
        "regex": "(content=MvMmall)",
        "type": "bodys",
    },

    "AirvaeCommerce": {
        "regex": "(E-Commerce Shopping Cart Software)",
        "type": "bodys",
    },

    "AiCart": {
        "regex": "(APP_authenticate)",
        "type": "bodys",
    },

    "MallBuilder": {
        "regex": "(content=MallBuilder | Powered by MallBuilder)",
        "type": "bodys",
    },

    "e-junkie": {
        "regex": "(function EJEJC_lc)",
        "type": "bodys",
    },

    "Allomani": {
        "regex": "(content=Allomani | Programmed By Allomani)",
        "type": "bodys",
    },

    "ASPilot-Cart": {
        "regex": "(content=Pilot Cart | /pilot_css_default.css)",
        "type": "bodys",
    },

    "Axous": {
        "regex": "(content=Axous | Axous Shareware Shop)",
        "type": "bodys",
    },

    "CaupoShop-Classic": {
        "regex": "(Powered by CaupoShop | <!-- CaupoShop Classic | <a href=http://www.caupo.net target=_blank>CaupoNet)",
        "type": "bodys",
    },

    "PretsaShop": {
        "regex": "(content=PrestaShop)",
        "type": "bodys",
    },

    "ComersusCart": {
        "regex": "(CONTENT=Powered by Comersus | href=comersus_showCart.asp)",
        "type": "bodys",
    },

    "Foxycart": {
        "regex": "(<script src=//cdn.foxycart.com)",
        "type": "bodys",
    },

    "DV-Cart": {
        "regex": "(class=KT_tngtable)",
        "type": "bodys",
    },

    "EarlyImpact-ProductCart": {
        "regex": "(fpassword.asp?redirectUrl=&frURL=Custva.asp)",
        "type": "bodys",
    },

    "Escenic": {
        "regex": "(content=Escenic | <!-- Start Escenic Analysis Engine client script -->)",
        "type": "bodys",
    },

    "ICEshop": {
        "regex": "(Powered by ICEshop | <div id=iceshop>)",
        "type": "bodys",
    },

    "Interspire-Shopping-Cart": {
        "regex": "(content=Interspire Shopping Cart | class=PoweredBy>Interspire Shopping Cart)",
        "type": "bodys",
    },

    "iScripts-MultiCart": {
        "regex": "(Powered by <a href=http://iscripts.com/multicart)",
        "type": "bodys",
    },

    "华天动力OA(OA8000)": {
        "regex": "(/OAapp/WebObjects/OAapp.woa)",
        "type": "bodys",
    },

    "通达OA": {
        "regex": "(<link rel=shortcut icon href=/images/tongda.ico /> | OA提示：不能登录OA | 紧急通知：今日10点停电 | Office Anywhere 2013| body = <a href='http://www.tongda2000.com/' target='_black'>通达官网</a></div>)",
        "type": "bodys",
    },

    "OA(a8/seeyon/ufida)": {
        "regex": "(/seeyon/USER-DATA/IMAGES/LOGIN/login.gif)",
        "type": "bodys",
    },

    "yongyoufe": {
        "regex": "(FE协作 | V_show | V_hedden)",
        "type": "bodys",
    },

    "pmway_E4_crm": {
        "regex": "(E4 | CRM)",
        "type": "headers",
    },

    "Dolibarr": {
        "regex": "(Dolibarr Development Team)",
        "type": "bodys",
    },

    "PHPOA": {
        "regex": "(admin_img/msg_bg.png)",
        "type": "bodys",
    },

    "78oa": {
        "regex": "(/resource/javascript/system/runtime.min.js | license.78oa.com | 78oa|src=/module/index.php)",
        "type": "bodys",
    },

    "WishOA": {
        "regex": "(WishOA_WebPlugin.js)",
        "type": "bodys",
    },

    "金和协同管理平台": {
        "regex": "(金和协同管理平台)",
        "type": "headers",
    },

    "Lotus": {
        "regex": "(IBM Lotus iNotes Login | iwaredir.nsf)",
        "type": "bodys",
    },

    "OA企业智能办公自动化系统": {
        "regex": "(input name=S1 type=image | count/mystat.asp)",
        "type": "bodys",
    },

    "ecwapoa": {
        "regex": "(ecwapoa)",
        "type": "bodys",
    },

    "ezOFFICE": {
        "regex": "(Wanhu ezOFFICE | EZOFFICEUSERNAME |万户OA | whirRootPath | /defaultroot/js/cookie.js)",
        "type": "bodys",
    },

    "任我行CRM": {
        "regex": "(任我行CRM | CRM_LASTLOGINUSERKEY)",
        "type": "bodys",
    },

    "信达OA": {
        "regex": "(http://www.xdoa.cn</a> | 北京创信达科技有限公司)",
        "type": "bodys",
    },

    "协众OA": {
        "regex": "( Powered by 协众OA | admin@cnoa.cn | Powered by CNOA.CN)",
        "type": "bodys",
    },

    "soffice": {
        "regex": "(OA办公管理平台)",
        "type": "headers",
    },

    "海天OA": {
        "regex": "(HTVOS.js)",
        "type": "bodys",
    },

    "泛微OA": {
        "regex": "(/js/jquery/jquery_wev8.js|/login/Login.jsp?logintype=1)",
        "type": "bodys",
    },

    "中望OA": {
        "regex": "(/app_qjuserinfo/qjuserinfoadd.jsp | /IMAGES/default/first/xtoa_logo.png)",
        "type": "bodys",
    },

    "睿博士云办公系统": {
        "regex": "(/studentSign/toLogin.di | /user/toUpdatePasswordPage.di)",
        "type": "bodys",
    },

    "一米OA": {
        "regex": "(/yimioa.apk)",
        "type": "bodys",
    },

    "泛普建筑工程施工OA": {
        "regex": "(/dwr/interface/LoginService.js)",
        "type": "bodys",
    },

    "正方OA": {
        "regex": "(zfoausername)",
        "type": "bodys",
    },

    "希尔OA": {
        "regex": "(/heeroa/login.do)",
        "type": "bodys",
    },

    "用友致远oa": {
        "regex": "(/seeyon/USER-DATA/IMAGES/LOGIN/login.gif | 用友致远A | /yyoa/ | /seeyon/common/all-min.js)",
        "type": "bodys",
    },

    "WordPress": {
        "regex": "(/wp-login.php?|wp-user)",
        "type": "bodys",
    },

    "宝塔面板": {
        "regex": "(<title>安全入口校验失败</title> | https://www.bt.cn/bbs/thread-18367-1-1.html)",
        "type": "bodys",
    },

    "Emlog": {
        "regex": "(/include/lib/js/common_tpl.js|content/templates)",
        "type": "bodys",
    },
    ###########自###########
    ###########定###########
    ###########义###########
    "ThinkPHP": {
        "regex": "(ThinkPHP|系统发生错误|无法载入模组|无法加载控制器|无法加载模块)",
        "type": "bodys",
        "path": "/?s=index2/index/index",
    },
    "蓝凌OA": {
        "regex": "(管理员登录)",
        "type": "bodys",
        "path": "/admin.do",
    },
}


class AttribDict(dict):
    """
    This class defines the dictionary with added capability to access members as attributes
    """

    def __init__(self, indict=None, attribute=None):
        if indict is None:
            indict = {}

        # Set any attributes here - before initialisation
        # these remain as normal attributes
        self.attribute = attribute
        dict.__init__(self, indict)
        self.__initialised = True

        # After initialisation, setting attributes
        # is the same as setting an item

    def __getattr__(self, item):
        """
        Maps values to attributes
        Only called if there *is NOT* an attribute with this name
        """

        try:
            return self.__getitem__(item)
        except KeyError:
            raise AttributeError("unable to access item '%s'" % item)

    def __setattr__(self, item, value):
        """
        Maps attributes to values
        Only if we are initialised
        """

        # This test allows attributes to be set in the __init__ method
        if "_AttribDict__initialised" not in self.__dict__:
            return dict.__setattr__(self, item, value)

        # Any normal attributes are handled normally
        elif item in self.__dict__:
            dict.__setattr__(self, item, value)

        else:
            self.__setitem__(item, value)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, dict):
        self.__dict__ = dict

    def __deepcopy__(self, memo):
        retVal = self.__class__()
        memo[id(self)] = retVal

        for attr in dir(self):
            if not attr.startswith('_'):
                value = getattr(self, attr)
                if not isinstance(value, (types.BuiltinFunctionType, types.FunctionType, types.MethodType)):
                    setattr(retVal, attr, copy.deepcopy(value, memo))

        for key, value in self.items():
            retVal.__setitem__(key, copy.deepcopy(value, memo))

        return retVal

class ruleInfo():
    def __init__(self, webInfo):
        self.rex = re.compile('<title>(.*?)</title>')
        self.webInfo = webInfo
        self.WebInfos = webInfo.WebInfos

    def main(self):
        for cms in ruleDatas:
            rulesRegex = re.compile(ruleDatas[cms]['regex'])
            
            #增量正则匹配
            if 'path' in ruleDatas[cms].keys():
                url = urlparse(list(self.WebInfos.keys())[0])
                self.webInfo.target = url.scheme + '://' + url.netloc + ruleDatas[cms]['path']
                self.webInfo.run()
            
            #默认正则匹配
            if 'headers' == ruleDatas[cms]['type']:
                result = self.heads(rulesRegex, cms)
                if result:
                    return result
            elif 'bodys' == ruleDatas[cms]['type']:
                result = self.bodys(rulesRegex, cms)
                if result:
                    return result
            elif 'codes' == ruleDatas[cms]['type']:
                result = self.codes(rulesRegex, cms)
                if result:
                    return result

        #所有正则表达式都不匹配的情况
        webTitle = ""
        webServer = ""
        for key in self.WebInfos:
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            webTitles = re.findall(self.rex, self.WebInfos[key][1])
            if webTitles:
                webTitle = webTitles[0]
            else:
                webTitle = "None"
            print("[{0}]\n".format(time.strftime("%H:%M:%S", time.localtime(
                ))), 
                "CMS: " + "None" + '\n', 
                "WebServer: " + webServer + '\n', 
                "WebStatus: " + str(self.WebInfos[key][2]) + '\n', 
                "URL: " + key + '\n', 
                "WebTitle: "+ webTitle + '\n')
        return webServer
        #return str(self.WebInfos[key][2])+','+webServer
        

    def heads(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            #返回头部字段是否包含server
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            #获取返回文本里的title
            try:
                webTitles = re.findall(self.rex, self.WebInfos[key][1])
                if webTitles:
                    webTitle = webTitles[0]
                else:
                    webTitle = "None"
            except Exception as e:
                webTitle = "None"
            #遍历返回头部字段值
            for head in self.WebInfos[key][0]:
                resHeads = re.findall(rulesRegex, self.WebInfos[key][0][head])
                if resHeads:
                    print("[{0}]\n".format(time.strftime("%H:%M:%S", time.localtime(
                        ))), 
                        "CMS: " + cms + '\n', 
                        "WebServer: " + webServer + '\n', 
                        "WebStatus: " + str(self.WebInfos[key][2]) + '\n', 
                        "URL: " + key + '\n', 
                        "WebTitle: "+ webTitle + '\n')
                    #return str(self.WebInfos[key][2])+','+cms
                    return cms

                    
    def bodys(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            #获取返回文本里的title
            try:
                webTitles = re.findall(self.rex, self.WebInfos[key][1])
                if webTitles:
                    webTitle = webTitles[0]
                else:
                    webTitle = "None"
            except Exception as e:
                webTitle = "None"
            resCodes = re.findall(rulesRegex, self.WebInfos[key][1])
            if resCodes:
                print("[{0}]\n".format(time.strftime("%H:%M:%S", time.localtime(
                    ))), 
                    "CMS: " + cms + '\n', 
                    "WebServer: " + webServer + '\n', 
                    "WebStatus: " + str(self.WebInfos[key][2]) + '\n', 
                    "URL: " + key + '\n', 
                    "WebTitle: "+ webTitle + '\n')
                #return str(self.WebInfos[key][2])+','+cms
                return cms

    def codes(self, rulesRegex, cms):
        webTitle = ""
        webServer = ""
        for key in list(self.WebInfos):
            #返回头部字段是否包含server
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
            else:
                webServer = "None"
            #获取返回文本里的title
            try:
                webTitles = re.findall(self.rex, self.WebInfos[key][1])
                if webTitles:
                    webTitle = webTitles[0]
                else:
                    webTitle = "None"
            except Exception as e:
                webTitle = "None"
            resCodes = re.findall(rulesRegex, str(self.WebInfos[key][2]))
            if resCodes:
                print("[{0}]\n".format(time.strftime("%H:%M:%S", time.localtime(
                    ))), 
                    "CMS: " + cms + '\n', 
                    "WebServer: " + webServer + '\n', 
                    "WebStatus: " + str(self.WebInfos[key][2]) + '\n',
                    "URL: " + key + '\n', 
                    "WebTitle: "+ webTitle + '\n')
                return cms


class webInfo():
    def __init__(self, target, WebInfos):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        }
        self.target = target
        self.WebInfos = WebInfos

    def run(self):
        s = requests.Session()
        s.keep_alive = False
        s.headers = self.headers
        # s.mount("http://", HTTPAdapter(max_retries=3))
        # s.mount("https://", HTTPAdapter(max_retries=3))
        s.verify = False
        shiroCookie = {'rememberMe': '1'}
        s.cookies.update(shiroCookie)
        try:
            req = s.get(self.target, timeout=2)
            webHeaders = req.headers
            webCodes = req.text
            #webCodes = req.text
            #webCodes = req.content.decode(encoding="utf-8", errors="ignore")
            
            self.WebInfos[self.target] = webHeaders, webCodes, req.status_code
            req.close()
            return True
        except requests.exceptions.ReadTimeout:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '请求超时')
            return None
        except requests.exceptions.ConnectionError:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '连接错误')
            return None
        except requests.exceptions.ChunkedEncodingError:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '编码错误')
            return None
        except Exception as e:
            print("[{0}]".format(time.strftime("%H:%M:%S", time.localtime(
                ))), self.target, '未知错误')
            return None


print("[*]识别CMS同时判断链接是否存活!")
def check(**kwargs):
    WebInfos = AttribDict()
    try:
        urls = kwargs['url'].strip('/')#/*str*/
        WebInfos_1 = webInfo(urls, WebInfos)
        WebInfos_2 = webInfo(urls.replace('http','https'), WebInfos)

        if WebInfos_1.run():
            ruleInfos = ruleInfo(WebInfos_1)
            webServer = ruleInfos.main()
            return webServer
        elif WebInfos_2.run():
            ruleInfos = ruleInfo(WebInfos_2)
            webServer = ruleInfos.main()
            return webServer
        else:
            return None
    except Exception as e:
        print('执行脚本出错 %s'%type(e))
        
if __name__ == "__main__":
    check(**{'url':'http://know.jxedu.gov.cn/Stulogin.jsp'})






