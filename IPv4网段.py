#!/usr/bin/env python3
# coding=utf-8

WangLuo = "192.168.1.1/24"   # IP地址。例如“192.168.0.1”或者“192.168.0.1/24”。当使用“192.168.0.1”必须使用掩码！
YanMa = ""                   # 掩码。当IP地址不带掩码位时，需要此参数。
MuLu = ""                    # 需批量计算的IP地址文件的目录。请使用“\\”来表示“\”。默认值为与py同目录。
WenJianMing = "ip_list.txt"  # ip网段文本文件名(批量解析IP段信息)

"""
ip网段文本的例子：
192.168.1.1/32
192.168.1.1/31
192.168.1.1/20
"""

import os
import sys
import ipaddress
import time

from datetime import datetime

#公共参数
IP_INFO_PATH = "" 
LogName = ""
str_split = ","

#添加分割符
def listtostr(LieBiao) -> str:
    s2 = ""
    for s1 in LieBiao :
        s2 = s2 + s1 + str_split
    return s2

#可用IP数量
def KeYong(host) -> int:
    temp = host.num_addresses
    i1 = host.prefixlen
    if i1 == 32 or i1 == 31:
        i2 = 1
    else:
        i2 = temp - 2
    return i2


#掩码表
def mask_save():
    if not os.path.exists("掩码表.csv"):
        with open("掩码表.csv","a+", newline = "") as file_log:
            s2 = listtostr(["掩码位长", "掩码", "可用数量"])
            file_log.write(s2 + os.linesep)
            for i in range(1, 33):
                print(str(i))
                net4 = ipaddress.ip_network("192.168.1.1/" + str(i), False)
                l1 = KeYong(net4)
                if net4.prefixlen == 32:
                    s2 = listtostr([str(i), str(net4.netmask), ""])
                else:
                    s2 = listtostr([str(i), str(net4.netmask), str(l1)])
                file_log.write(s2 + os.linesep)
            file_log.close

#保存日志
def log_save(LieBiao):
    s2 = listtostr(LieBiao)
    with open(LogName,"a+", newline = "") as file_log:
        file_log.write(s2 + os.linesep) 
        file_log.close

# 读取文本，获取ip网段信息
def get_ips_info():
    try:
        with open(IP_INFO_PATH, 'r') as f:
            for line in f.readlines():
                # 去掉前后空白
                line = line.strip()
                # 忽略空格行，len=1
                if (
                        len(line) == 1 or
                        line.startswith('#')
                ):
                    continue

                yield line

    except FileNotFoundError :
        print('Can not find "{}"'.format(IP_INFO_PATH))
    except IndexError :
        print('"{}" format error'.format(IP_INFO_PATH))

def get_ip_list(ip):

    #计算地址范围
    net4 = ipaddress.ip_network(ip, False)

    #可用IP
    i3 = KeYong(net4)
    i1 = net4.prefixlen
    if i1 == 32 or i1 == 31:
        s10 = str(net4[0])
        s11 = str(net4[0])
    else:
        s10 = str(net4[1])
        s11 = str(net4[-2])


    #广播地址
    if i1 == 32:
        s1 = " 唯一地址"
    else:
        s1 = str(net4.broadcast_address)

    

    #输出
    print("")
    print(net4.with_prefixlen)
    print("第一个可用IP地址：" + s10)
    print("最后一个可用IP地址：" + s11)
    print("广播地址：" + s1)
    print("掩码：" + str(net4.netmask))
    print("反掩码（用于ACL规则）：" + str(net4.hostmask))
    print("可用IP总数：" + str(i3))
    print("")

    #保存日志
    log_save([net4.with_prefixlen, s10, s11, str(s1), str(net4.netmask), str(net4.hostmask),str(i3)])


if __name__ == '__main__':

    #日志文件名
    LogTime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    LogName = "IP_LIST_" + LogTime + ".csv"

    #开始时间
    start_time = datetime.now()


    #创建日志
    my_file = "LOG" + os.sep
    
    ArgRoot = os.path.dirname(os.path.abspath(sys.argv[0]))
    print(ArgRoot)
    os.chdir(ArgRoot)

    dirname = os.path.abspath(".")
    my_file = os.path.abspath(my_file)
    if not os.path.exists(my_file):
        os.makedirs(my_file) 

    print(dirname)

    LogName = my_file + os.sep + LogName

    log_save(["IP段","第一个可用IP地址", "最后一个可用IP地址" , "广播地址", "掩码", "反掩码（用于ACL规则）", "总计IP数"])

    #掩码表
    mask_save()

    #核心。IP段的相关信息
    if "\\" in WangLuo :
        WangLuo = WangLuo.replace('\\','/')
    if ("." in WangLuo) and (not "/" in WangLuo):
        WangLuo = WangLuo + '/' + YanMa

    if "/"  in WangLuo :
        get_ip_list(WangLuo)

    #读取列表TXT
    if MuLu == "":
        IP_INFO_PATH = WenJianMing
    elif os.listdir(MuLu):
        if MuLu[-1] == os.sep:
            IP_INFO_PATH = MuLu + WenJianMing
        else:
            IP_INFO_PATH = MuLu + os.sep + WenJianMing
    if os.path.exists(IP_INFO_PATH):
        ips_list = get_ips_info()
        for ips in ips_list:
            get_ip_list(ips)


    #结束语
    end_time = datetime.now()
    print('All done.总花费时间{:0.2f}s.'.format((end_time - start_time).total_seconds()))

    #暂停，看结果
    time.sleep(1200)