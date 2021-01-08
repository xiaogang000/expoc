#!/usr/bin/env python
# author:Xiaogang
# Help: FLink <1.9.1 代码执行
# fofa "apache-flink-dashboard" && country="US"


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
	url = 'http://{}:8081/jar/upload'.format(ip)
	try:
		res = requests.request("GET", url=url, timeout=10)
		if "jar/upload" in res.text:
			result = {
				'IP': ip,
				'URL': url,
				'response': res.text
			}
			print(result)
	except Exception as e:
		print("连接发生错误：{}".format(ip))


def main():
	args = sys.argv
	if args[1] == '-t':
		iplist = get_iplist(args[2])
		pool = ThreadPool(10)
		pool.map(check, iplist)
	else:
		print("Usage: python {} -t 123.txt".format(args[0]))


if __name__ == '__main__':
	main()
