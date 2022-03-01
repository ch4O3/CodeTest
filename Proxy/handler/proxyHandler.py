# -*- coding: utf-8 -*-
# from hutaow
import sys
import socket
import logging
import threading
import random
local_ip = '127.0.0.1'
local_port = 10086
PKT_BUFF_SIZE = 2048
#日志设置
logger = logging.getLogger("Proxy Logging")
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(lineno)-4d %(message)s', '%Y %b %d %a %H:%M:%S',)
stream_handler = logging.StreamHandler(sys.stderr)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logger.setLevel(logging.DEBUG)

def tcp_mapping_worker(conn_receiver, conn_sender):
    while True:
        try:
            data = conn_receiver.recv(PKT_BUFF_SIZE)
        except Exception:
            print('Connection closed.')
            break
        if not data:
            print('No more data is received.')
            break
        try:
            conn_sender.sendall(data)
        except Exception:
            print('Failed sending data.')
            break
        print('Mapping > %s -> %s > %d bytes.' % (conn_receiver.getpeername(), conn_sender.getpeername(), len(data)))
    conn_receiver.close()
    conn_sender.close()
    return

def tcp_mapping_request(local_conn, remote_ip, remote_port):
    
    while True:
        remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote_conn.settimeout(3)
            remote_conn.connect((remote_ip, remote_port))
        except Exception:
            print('Unable to connect to the remote server.')
            continue
        threading.Thread(target=tcp_mapping_worker, args=(local_conn, remote_conn)).start()
        threading.Thread(target=tcp_mapping_worker, args=(remote_conn, local_conn)).start()
        return

def switchPro(proxylist):
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.bind((local_ip, local_port))
    local_server.listen(5)
    #logger.debug('Starting mapping service on ' + local_ip + ':' + str(local_port) + ' ...')
    print('Starting mapping service on ' + local_ip + ':' + str(local_port) + ' ...')

    while True:
        try:
            (local_conn, local_addr) = local_server.accept()
            proxyip = random.choice(proxylist)
            print("[!]Now proxy ip:"+str(proxyip))
            prip, prpo = proxyip.split(":")
        except Exception:
            local_server.close()
            print('Stop mapping service.')
            #logger.debug('Stop mapping service.')
            break
        threading.Thread(target=tcp_mapping_request, args=(local_conn, prip, prpo)).start()
        print('Receive mapping request from %s:%d.' % local_addr)


def Loadips():
    ip_list = []
    ip = ['ip','port']
    with open('ips.txt') as ips:
        lines = ips.readlines()
    for line in lines:
        ip[0],ip[1] = line.strip().split(":")
        ip[1] = eval(ip[1])
        nip = tuple(ip)
        ip_list.append(nip)
    return ip_list

if __name__ == '__main__':
    a =  Loadips()
    print(a)
    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server.bind((local_ip, local_port))
    local_server.listen(5)
    logger.debug('Starting mapping service on ' + local_ip + ':' + str(local_port) + ' ...')
    while True:
        try:
            (local_conn, local_addr) = local_server.accept()
            proxyip = random.choice(a)
            print("[!]Now proxy ip:"+str(proxyip))
            prip = proxyip[0]
            prpo= proxyip[1]
        except Exception:
            local_server.close()
            logger.debug('Stop mapping service.')
            break
        threading.Thread(target=tcp_mapping_request, args=(local_conn, prip, prpo)).start()
        logger.debug('Receive mapping request from %s:%d.' % local_addr)