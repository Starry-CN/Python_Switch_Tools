#!/usr/bin/env python3
# -*- coding:UTF-8 -*-



#检测计算机的当前网络


ChaoShi = 0.5                  # Ping时，等待每次回复的超时时间(秒)


try:
    from pip.internal import main
except Exception:
    from pip._internal import main as main

try:
    from pythonping import ping
    import netifaces
except Exception:
    main(['install','-i', 'https://mirrors.huaweicloud.com/repository/pypi/simple', 'pythonping', 'netifaces'])
    from pythonping import ping
    import netifaces

from multiprocessing import freeze_support
from multiprocessing.pool import ThreadPool
from datetime import datetime, time

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
Log_Off_Str = ""
Log_On_Str  = ""

# 线程数()
THREADING_NUM = 10
# 进程池
pool = ThreadPool(THREADING_NUM)
# 线程锁
queueLock = threading.Lock()
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
    global ChaoShi
    delay = ping(target_ip, count=2, timeout=ChaoShi)

    if delay.success(option=1):
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
    net4 = ipaddress.ip_network(ip, False)
    temp = net4.hosts()
    ip_list = []

    if not ipaddress.ip_address('127.0.0.1') in net4:
        print(net4.with_prefixlen)
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




    #批量Ping各个网卡
    nets =netifaces.interfaces()
    for net1 in nets:
        try:
            addrs = netifaces.ifaddresses(net1)
            do_pings(str(addrs[netifaces.AF_INET][0]['addr']) + '/' + str(addrs[netifaces.AF_INET][0]['netmask']))
        except Exception:
            pass
    pool.close()
    pool.join()

    #结束语
    end_time = datetime.now()
    print('All done.总花费时间{:0.3f}s.'.format((end_time - start_time).total_seconds()))

    #暂停，看结果
    time.sleep(1200)

