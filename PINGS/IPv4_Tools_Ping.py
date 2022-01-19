#!/usr/bin/env python3
# -*- coding:UTF-8 -*-

#代码来源：
#www.jianshu.com/p/6740a8e36a06

#网络复杂，首发未知

#如有侵权，那么必删

WangLuo = "192.168.1.1/24"   # IP地址。例如“192.168.0.1”或者“192.168.0.1/24”。当使用“192.168.0.1”必须使用掩码！
YanMa = ""                   # 掩码。当IP地址不带掩码位时，需要此参数。
MuLu = ""                    # 需批量计算的IP地址文件的目录。请使用“\\”来表示“\”。默认值为与py同目录。
WenJianMing = "ip_list.txt"  # ip网段文本文件名(批量解析IP段信息)
ChaoShi = 600                # Ping时，等待每次回复的超时时间(毫秒)

"""
ip网段文本的例子：
192.168.1.1/24
192.168.2.1/24
192.168.3.1/24
"""

from multiprocessing import freeze_support
from multiprocessing.pool import ThreadPool
from datetime import datetime, time

import subprocess
import ipaddress
import threading
import sys
import os
import time

# ip网段文本路径(当前目录下)
IP_INFO_PATH = ""

#不在线日志
Log_Off = ""
Log_On  = ""

# 线程数()
THREADING_NUM = 10
# 进程池
pool = ThreadPool(THREADING_NUM)
# 线程锁
queueLock = threading.Lock()
# 中断运行
isstop = False
# 全局变量
str_split = ","

#保存日志
def log_save(FileName, stc):
    queueLock.acquire()
    with open(FileName,"a+", newline = "") as file_log:
        file_log.write(stc + str_split + os.linesep) 
        file_log.close
    queueLock.release()

# 打印消息
def show_info(msg):
    queueLock.acquire()
    print(msg)
    queueLock.release()

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

    except FileNotFoundError as e:
        show_info('Can not find "{}"'.format(IP_INFO_PATH))
    except IndexError as e:
        show_info('"{}" format error'.format(IP_INFO_PATH))

def do_one_ping(target_ip) -> bool :
    """
    单次ping测试
    """
    global isstop
    if sys.platform == 'linux':
        res = subprocess.call(['ping', '-c', '2', '-W', str(ChaoShi), target_ip], stdout = subprocess.PIPE)
    if sys.platform == 'win32':
        res = subprocess.call(['ping', '-n', '2', '-w', str(ChaoShi), target_ip], stdout = subprocess.PIPE)
    else:  
        isstop = True
        show_info('不支持该平台系统，非常抱歉!')
        
    if isstop:
        time.sleep(3)
        exit(1)

    if type(res) is int:
        if res == 0:
            show_info('%-20s%-20s' % (target_ip, '在线'))
            return True
        else:
            return False
    elif res.returncode == 0:
        show_info('%-20s%-20s' % (target_ip, '在线'))
        return True
    else:
        return False

def do_ping(target_ip):
    """
    是否在线，写入日志
    """
    global Log_On, Log_Off
    b = do_one_ping(target_ip) 
    if b:
        # ping成功
        log_save(Log_On,  target_ip)
    else:
        # ping失败
        log_save(Log_Off, target_ip)


def get_ip_list(ip):
    """
    获取ip列表
    """
    temp = ipaddress.ip_network(ip, False).hosts()
    ip_list = []
    for item in temp:
        ip_list.append(str(item))
    return ip_list

def do_pings(ip_str):
    """
    循环Ping
    """
    ip_list = get_ip_list(ip_str)
    print("正在工作中，请稍等……")
    for ip in ip_list:
        pool.apply_async(do_ping, args=(ip,))


if __name__ == '__main__':

    freeze_support()
    #开始时间
    start_time = datetime.now()

    #日志文件名
    LogTime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    Log_Off = "不在线IP_" + LogTime + ".csv"
    Log_On = "在线IP_" + LogTime + ".csv"


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

    Log_Off = my_file + os.sep + Log_Off
    Log_On  = my_file + os.sep + Log_On

    log_save(Log_Off, "IP地址")
    log_save(Log_On , "IP地址")


    #核心。Ping单个网段
    if "\\" in WangLuo :
        WangLuo = WangLuo.replace('\\','/')
    if ("." in WangLuo) and (not "/" in WangLuo):
        WangLuo = WangLuo + '/' + YanMa

    if "/"  in WangLuo :
        do_pings(WangLuo)

    #读取列表TXT。批量Ping
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
            do_pings(ips)
    pool.close()
    pool.join()

    #结束语
    end_time = datetime.now()
    print('All done.总花费时间{:0.3f}s.'.format((end_time - start_time).total_seconds()))

    #暂停，看结果
    time.sleep(1200)

