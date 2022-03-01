# -*- coding: utf-8 -*-
# from hutaow
import sys
import socket
import logging
import threading
import random
import json
local_ip = '127.0.0.1'
local_port = 9999
PKT_BUFF_SIZE = 2048
logger = logging.getLogger("Proxy Logging")
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(lineno)-4d %(message)s', '%Y %b %d %a %H:%M:%S',)
stream_handler = logging.StreamHandler(sys.stderr)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)
logger.setLevel(logging.DEBUG)
def tcp_mapping_worker(conn_receiver, conn_sender):
    while True:
        if conn_receiver.fileno() == -1 or conn_sender.fileno() == -1:
            logger.debug('Socket has closed. ')
            return
        #if getattr(conn_receiver, '_closed') == True or getattr(conn_sender, '_closed') == True:
        try:
            data = conn_receiver.recv(PKT_BUFF_SIZE)
        except Exception as e:
            logger.debug('Connection closed. %s'%e)
            break
        if not data:
            logger.info('No more data is received.')
            break
        try:
            conn_sender.sendall(data)
        except Exception as e:
            logger.error('Failed sending data. %s'%e)
            break
        logger.info('Mapping > %s -> %s > %d bytes.' % (conn_receiver.getpeername(), conn_sender.getpeername(), len(data)))
        #else:
            #return
    conn_receiver.close()
    conn_sender.close()
    return

def tcp_mapping_request(local_conn, remote_ip, remote_port):
    #切换IP次数
    retry_sock = 2
    #单个连接最大重试次数
    retry_count = 1
    while True:
        remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote_conn.settimeout(2)
            remote_conn.connect((remote_ip, remote_port))
        except Exception:
            if retry_count > 0:
                logger.error('Unable to connect to the remote server. Number of retries remaining %s'%retry_count)
                retry_count -= 1
                continue
            elif retry_sock > 0:
                #重置重试次数
                retry_count = 1
                #切换IP次数减一
                retry_sock -= 1
                proxyip = random.choice(a)
                print("[!]Switch proxy ip:"+str(proxyip))
                remote_ip = proxyip[0]
                remote_port= proxyip[1]
                continue
            else:
                #代理不稳定，建议切换
                logger.info('Proxy is not stability.')
                local_conn.close()
                remote_conn.close()
                return
                
        threading.Thread(target=tcp_mapping_worker, args=(local_conn, remote_conn)).start()
        threading.Thread(target=tcp_mapping_worker, args=(remote_conn, local_conn)).start()
        return

def Loadips():
    ip_list = []
    ip = ['ip','port']
    with open('ips.txt') as ips:
        lines = ips.readlines()
    for line in lines:
        proxy = json.loads(line.strip()).get("proxy", "")
        ip[0],ip[1] = proxy.split(":")
        ip[1] = eval(ip[1])
        nip = tuple(ip)
        ip_list.append(nip)
    return ip_list

a =  Loadips()

if __name__ == '__main__':
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