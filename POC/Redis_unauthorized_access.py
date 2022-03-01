#!/usr/bin/python

import socket

vuln = ['redis', '6379']

print('[*]Usage: [IP]')
def check(**kwargs):
    ip = kwargs['ip']
    port = int(6379)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((ip, port))
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s.send(payload)
        data = s.recv(1024)
        s.close()
        if b"redis_version" in data:
            print('[+]6379 Redis Unauthorized Access')
        else:
            print('[-]target is not vulnerable')
    except Exception as e:
        s.close()




