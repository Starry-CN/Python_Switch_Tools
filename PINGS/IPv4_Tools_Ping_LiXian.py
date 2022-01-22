#!/usr/bin/env python
# -*- coding:UTF-8 -*-


MuLu = ""                    # 需批量计算的IP地址文件的目录。请使用“\\”来表示“\”。默认值为与py同目录。
WenJianMing = "ip_list.txt"  # ip网段文本文件名(批量解析IP段信息)

# 修改Ping代码（合并Ping3代码）

import os
from posixpath import dirname
import socket
import struct
import select
import time
import platform
import zlib
import logging
import functools
import errno
import ipaddress
import threading
import sys
import enum

from multiprocessing import freeze_support
from multiprocessing.pool import ThreadPool
from datetime import datetime

__version__ = "3.0.2"
DEBUG = False  # DEBUG: Show debug info for developers. (default False)
EXCEPTIONS = False  # EXCEPTIONS: Raise exception when delay is not available.
LOGGER = None  # LOGGER: Record logs into console or file.

IP_HEADER_FORMAT = "!BBHHHBBHII"
ICMP_HEADER_FORMAT = "!BBHHH"  # According to netinet/ip_icmp.h. !=network byte order(big-endian), B=unsigned char, H=unsigned short
ICMP_TIME_FORMAT = "!d"  # d=double
SOCKET_SO_BINDTODEVICE = 25  # socket.SO_BINDTODEVICE
ICMP_DEFAULT_CODE = 0  # the code for ECHO_REPLY and ECHO_REQUEST

# ip网段文本路径(当前目录下)
IP_INFO_PATH = ""

# 线程数()
THREADING_NUM = 20
# 进程池
pool = ThreadPool(THREADING_NUM)
# 线程锁
queueLock = threading.Lock()

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




class IcmpType(enum.IntEnum):
    """Enum for Type in ICMP Header."""
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT_MESSAGE = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    BAD_IP_HEADER = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14


class IcmpDestinationUnreachableCode(enum.IntEnum):
    """Enum for Code in ICMP Header when type is DESTINATION_UNREACHABLE (3)"""
    DESTINATION_NETWORK_UNREACHABLE = 0
    DESTINATION_HOST_UNREACHABLE = 1
    DESTINATION_PROTOCOL_UNREACHABLE = 2
    DESTINATION_PORT_UNREACHABLE = 3
    FRAGMENTATION_REQUIRED = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    NETWORK_ADMINISTRATIVELY_PROHIBITED = 9
    HOST_ADMINISTRATIVELY_PROHIBITED = 10
    NETWORK_UNREACHABLE_FOR_TOS = 11
    HOST_UNREACHABLE_FOR_TOS = 12
    COMMUNICATION_ADMINISTRATIVELY_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF_IN_EFFECT = 15


class IcmpTimeExceededCode(enum.IntEnum):
    """Enum for Code in ICMP Header when type is TIME_EXCEEDED (11)"""
    TTL_EXPIRED = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1


class PingError(Exception):
    pass


class TimeExceeded(PingError):
    pass


class TimeToLiveExpired(TimeExceeded):
    def __init__(self, message="Time exceeded: Time To Live expired."):
        super().__init__(message)


class DestinationUnreachable(PingError):
    pass


class DestinationHostUnreachable(DestinationUnreachable):
    def __init__(self, dest_addr=None):
        message = "Destination unreachable: Host unreachable."
        if dest_addr:
            message += " (Host='{}')".format(dest_addr)
        super().__init__(message)


class HostUnknown(PingError):
    def __init__(self, dest_addr=None):
        message = "Cannot resolve: Unknown host."
        if dest_addr:
            message += " (Host='{}')".format(dest_addr)
        super().__init__(message)


class Timeout(PingError):
    def __init__(self, timeout=None):
        message = "Request timeout for ICMP packet."
        if timeout is not None:
            message += " (Timeout={}s)".format(timeout)
        super().__init__(message)


def _debug(*args, **kwargs):
    """Print debug info to stdout if `ping3.DEBUG` is True.

    Args:
        *args: Any. Usually are strings or objects that can be converted to str.
    """
    def get_logger():
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        cout_handler = logging.StreamHandler()
        cout_handler.setLevel(logging.DEBUG)
        cout_handler.setFormatter(formatter)
        logger.addHandler(cout_handler)
        logger.debug("Ping3 Version: {}".format(__version__))
        logger.debug("LOGGER: {}".format(logger))
        return logger

    if not DEBUG:
        return None
    global LOGGER
    LOGGER = LOGGER or get_logger()
    message = " ".join(str(item) for item in args)
    LOGGER.debug(message)

def _raise(err):
    """Raise exception if `ping3.EXCEPTIONS` is True.

    Args:
        err: Exception.

    Raise:
        Exception: Exception passed in args will be raised if `ping3.EXCEPTIONS` is True.
    """
    if EXCEPTIONS:
        raise err


def _func_logger(func: callable) -> callable:
    """Decorator that log function calls for debug

    Args:
        func: Function to be decorated.

    Returns:
        Decorated function.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        pargs = ", ".join("'{}'".format(arg) if isinstance(arg, str) else arg for arg in args)
        kargs = str(kwargs) if kwargs else ""
        all_args = ", ".join((pargs, kargs)) if (pargs and kargs) else (pargs or kargs)
        _debug("Function called:", "{func.__name__}({})".format(all_args, func=func))
        func_return = func(*args, **kwargs)
        _debug("Function returned:", "{func.__name__} -> {rtrn}".format(func=func, rtrn=func_return))
        return func_return

    return wrapper


def checksum(source: bytes) -> int:
    """Calculates the checksum of the input bytes.

    RFC1071: https://tools.ietf.org/html/rfc1071
    RFC792: https://tools.ietf.org/html/rfc792

    Args:
        source: Bytes. The input to be calculated.

    Returns:
        int: Calculated checksum.
    """
    BITS = 16  # 16-bit long
    carry = 1 << BITS  # 0x10000
    result = sum(source[::2]) + (sum(source[1::2]) << (BITS // 2))  # Even bytes (odd indexes) shift 1 byte to the left.
    while result >= carry:  # Ones' complement sum.
        result = sum(divmod(result, carry))  # Each carry add to right most bit.
    return ~result & ((1 << BITS) - 1)  # Ensure 16-bit


def read_icmp_header(raw: bytes) -> dict:
    """Get information from raw ICMP header data.

    Args:
        raw: Bytes. Raw data of ICMP header.

    Returns:
        A map contains the infos from the raw header.
    """
    icmp_header_keys = ('type', 'code', 'checksum', 'id', 'seq')
    return dict(zip(icmp_header_keys, struct.unpack(ICMP_HEADER_FORMAT, raw)))


def read_ip_header(raw: bytes) -> dict:
    """Get information from raw IP header data.

    Args:
        raw: Bytes. Raw data of IP header.

    Returns:
        A map contains the infos from the raw header.
    """
    def stringify_ip(ip: int) -> str:
        return ".".join(str(ip >> offset & 0xff) for offset in (24, 16, 8, 0))  # str(ipaddress.ip_address(ip))

    ip_header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
    ip_header = dict(zip(ip_header_keys, struct.unpack(IP_HEADER_FORMAT, raw)))
    ip_header['src_addr'] = stringify_ip(ip_header['src_addr'])
    ip_header['dest_addr'] = stringify_ip(ip_header['dest_addr'])
    return ip_header


@_func_logger
def send_one_ping(sock: socket, dest_addr: str, icmp_id: int, seq: int, size: int):
    """Sends one ping to the given destination.

    ICMP Header (bits): type (8), code (8), checksum (16), id (16), sequence (16)
    ICMP Payload: time (double), data
    ICMP Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

    Args:
        sock: Socket.
        dest_addr: The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"
        icmp_id: ICMP packet id. Calculated from Process ID and Thread ID.
        seq: ICMP packet sequence, usually increases from 0 in the same process.
        size: The ICMP packet payload size in bytes. Note this is only for the payload part.

    Raises:
        HostUnkown: If destination address is a domain name and cannot resolved.
    """
    _debug("Destination address: '{}'".format(dest_addr))
    try:
        dest_addr = socket.gethostbyname(dest_addr)  # Domain name will translated into IP address, and IP address leaves unchanged.
    except socket.gaierror as err:
        raise HostUnknown(dest_addr) from err
    _debug("Destination IP address:", dest_addr)
    pseudo_checksum = 0  # Pseudo checksum is used to calculate the real checksum.
    icmp_header = struct.pack(ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, pseudo_checksum, icmp_id, seq)
    padding = (size - struct.calcsize(ICMP_TIME_FORMAT)) * "Q"  # Using double to store current time.
    icmp_payload = struct.pack(ICMP_TIME_FORMAT, time.time()) + padding.encode()
    real_checksum = checksum(icmp_header + icmp_payload)  # Calculates the checksum on the dummy header and the icmp_payload.
    # Don't know why I need socket.htons() on real_checksum since ICMP_HEADER_FORMAT already in Network Bytes Order (big-endian)
    icmp_header = struct.pack(ICMP_HEADER_FORMAT, IcmpType.ECHO_REQUEST, ICMP_DEFAULT_CODE, socket.htons(real_checksum), icmp_id, seq)  # Put real checksum into ICMP header.
    _debug("Sent ICMP header:", read_icmp_header(icmp_header))
    _debug("Sent ICMP payload:", icmp_payload)
    packet = icmp_header + icmp_payload
    sock.sendto(packet, (dest_addr, 0))  # addr = (ip, port). Port is 0 respectively the OS default behavior will be used.


@_func_logger
def receive_one_ping(sock: socket, icmp_id: int, seq: int, timeout: int) -> float:
    """Receives the ping from the socket.

    IP Header (bits): version (8), type of service (8), length (16), id (16), flags (16), time to live (8), protocol (8), checksum (16), source ip (32), destination ip (32).
    ICMP Packet (bytes): IP Header (20), ICMP Header (8), ICMP Payload (*).
    Ping Wikipedia: https://en.wikipedia.org/wiki/Ping_(networking_utility)
    ToS (Type of Service) in IP header for ICMP is 0. Protocol in IP header for ICMP is 1.

    Args:
        sock: The same socket used for send the ping.
        icmp_id: ICMP packet id. Sent packet id should be identical with received packet id.
        seq: ICMP packet sequence. Sent packet sequence should be identical with received packet sequence.
        timeout: Timeout in seconds.

    Returns:
        The delay in seconds or None on timeout.

    Raises:
        TimeToLiveExpired: If the Time-To-Live in IP Header is not large enough for destination.
        TimeExceeded: If time exceeded but Time-To-Live does not expired.
        DestinationHostUnreachable: If the destination host is unreachable.
        DestinationUnreachable: If the destination is unreachable.
    """
    has_ip_header = (os.name != 'posix') or (platform.system() == 'Darwin') or (sock.type == socket.SOCK_RAW)  # No IP Header when unprivileged on Linux.
    if has_ip_header:
        ip_header_slice = slice(0, struct.calcsize(IP_HEADER_FORMAT))  # [0:20]
        icmp_header_slice = slice(ip_header_slice.stop, ip_header_slice.stop + struct.calcsize(ICMP_HEADER_FORMAT))  # [20:28]
    else:
        _debug("Unprivileged on Linux")
        icmp_header_slice = slice(0, struct.calcsize(ICMP_HEADER_FORMAT))  # [0:8]
    timeout_time = time.time() + timeout  # Exactly time when timeout.
    _debug("Timeout time: {} ({})".format(time.ctime(timeout_time), timeout_time))
    while True:
        timeout_left = timeout_time - time.time()  # How many seconds left until timeout.
        timeout_left = timeout_left if timeout_left > 0 else 0  # Timeout must be non-negative
        _debug("Timeout left: {:.2f}s".format(timeout_left))
        selected = select.select([sock, ], [], [], timeout_left)  # Wait until sock is ready to read or time is out.
        if selected[0] == []:  # Timeout
            raise Timeout(timeout)
        time_recv = time.time()
        _debug("Received time: {} ({}))".format(time.ctime(time_recv), time_recv))
        recv_data, addr = sock.recvfrom(1500)  # Single packet size limit is 65535 bytes, but usually the network packet limit is 1500 bytes.
        if has_ip_header:
            ip_header_raw = recv_data[ip_header_slice]
            ip_header = read_ip_header(ip_header_raw)
            _debug("Received IP header:", ip_header)
        icmp_header_raw, icmp_payload_raw = recv_data[icmp_header_slice], recv_data[icmp_header_slice.stop:]
        icmp_header = read_icmp_header(icmp_header_raw)
        _debug("Received ICMP header:", icmp_header)
        _debug("Received ICMP payload:", icmp_payload_raw)
        if not has_ip_header:  # When unprivileged on Linux, ICMP ID is rewrited by kernel.
            icmp_id = sock.getsockname()[1]  # According to https://stackoverflow.com/a/14023878/4528364
        if icmp_header['id'] and icmp_header['id'] != icmp_id:  # ECHO_REPLY should match the ID field.
            _debug("ICMP ID dismatch. Packet filtered out.")
            continue
        if icmp_header['type'] == IcmpType.TIME_EXCEEDED:  # TIME_EXCEEDED has no icmp_id and icmp_seq. Usually they are 0.
            if icmp_header['code'] == IcmpTimeExceededCode.TTL_EXPIRED:
                raise TimeToLiveExpired()  # Some router does not report TTL expired and then timeout shows.
            raise TimeExceeded()
        if icmp_header['type'] == IcmpType.DESTINATION_UNREACHABLE:  # DESTINATION_UNREACHABLE has no icmp_id and icmp_seq. Usually they are 0.
            if icmp_header['code'] == IcmpDestinationUnreachableCode.DESTINATION_HOST_UNREACHABLE:
                raise DestinationHostUnreachable()
            raise DestinationUnreachable()
        if icmp_header['id'] and icmp_header['seq'] == seq:  # ECHO_REPLY should match the SEQ field.
            if icmp_header['type'] == IcmpType.ECHO_REQUEST:  # filters out the ECHO_REQUEST itself.
                _debug("ECHO_REQUEST received. Packet filtered out.")
                continue
            if icmp_header['type'] == IcmpType.ECHO_REPLY:
                time_sent = struct.unpack(ICMP_TIME_FORMAT, icmp_payload_raw[0:struct.calcsize(ICMP_TIME_FORMAT)])[0]
                _debug("Received sent time: {} ({})".format(time.ctime(time_sent), time_sent))
                return time_recv - time_sent
        _debug("Uncatched ICMP packet:", icmp_header)


@_func_logger
def ping(dest_addr: str, timeout: int = 1, unit: str = "s", src_addr: str = None, ttl: int = None, seq: int = 0, size: int = 56, interface: str = None) -> float:
    """
    Send one ping to destination address with the given timeout.

    Args:
        dest_addr: The destination address, can be an IP address or a domain name. Ex. "192.168.1.1"/"example.com"
        timeout: Time to wait for a response, in seconds. Default is 4s, same as Windows CMD. (default 4)
        unit: The unit of returned value. "s" for seconds, "ms" for milliseconds. (default "s")
        src_addr: The IP address to ping from. This is for multiple network interfaces. Ex. "192.168.1.20". (default None)
        interface: LINUX ONLY. The gateway network interface to ping from. Ex. "wlan0". (default None)
        ttl: The Time-To-Live of the outgoing packet. Default is None, which means using OS default ttl -- 64 onLinux and macOS, and 128 on Windows. (default None)
        seq: ICMP packet sequence, usually increases from 0 in the same process. (default 0)
        size: The ICMP packet payload size in bytes. If the input of this is less than the bytes of a double format (usually 8), the size of ICMP packet payload is 8 bytes to hold a time. The max should be the router_MTU(Usually 1480) - IP_Header(20) - ICMP_Header(8). Default is 56, same as in macOS. (default 56)

    Returns:
        The delay in seconds/milliseconds, False on error and None on timeout.

    Raises:
        PingError: Any PingError will raise again if `ping3.EXCEPTIONS` is True.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError as err:
        if err.errno == errno.EPERM:  # [Errno 1] Operation not permitted
            _debug("`{}` when create socket.SOCK_RAW, using socket.SOCK_DGRAM instead.".format(err))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        else:
            raise err
    with sock:
        if ttl:
            try:  # IPPROTO_IP is for Windows and BSD Linux.
                if sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL):
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            except OSError as err:
                _debug("Set Socket Option `IP_TTL` in `IPPROTO_IP` Failed: {}".format(err))
            try:
                if sock.getsockopt(socket.SOL_IP, socket.IP_TTL):
                    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            except OSError as err:
                _debug("Set Socket Option `IP_TTL` in `SOL_IP` Failed: {}".format(err))
        if interface:
            sock.setsockopt(socket.SOL_SOCKET, SOCKET_SO_BINDTODEVICE, interface.encode())  # packets will be sent from specified interface.
            _debug("Socket Interface Binded:", interface)
        if src_addr:
            sock.bind((src_addr, 0))  # only packets send to src_addr are received.
            _debug("Socket Source Address Binded:", src_addr)
        thread_id = threading.get_native_id() if hasattr(threading, 'get_native_id') else threading.currentThread().ident  # threading.get_native_id() is supported >= python3.8.
        process_id = os.getpid()  # If ping() run under different process, thread_id may be identical.
        icmp_id = zlib.crc32("{}{}".format(process_id, thread_id).encode()) & 0xffff  # to avoid icmp_id collision.
        try:
            send_one_ping(sock=sock, dest_addr=dest_addr, icmp_id=icmp_id, seq=seq, size=size)
            delay = receive_one_ping(sock=sock, icmp_id=icmp_id, seq=seq, timeout=timeout)  # in seconds
        except Timeout as err:
            _debug(err)
            _raise(err)
            return None
        except PingError as err:
            _debug(err)
            _raise(err)
            return False
        if delay is None:
            return None
        if unit == "ms":
            delay *= 1000  # in milliseconds
        return delay


@_func_logger
def verbose_ping(dest_addr: str, count: int = 4, interval: float = 0, *args, **kwargs):
    """
    Send pings to destination address with the given timeout and display the result.

    Args:
        dest_addr: The destination address. Ex. "192.168.1.1"/"example.com"
        count: How many pings should be sent. 0 means infinite loops until manually stopped. Default is 4, same as Windows CMD. (default 4)
        interval: How many seconds between two packets. Default is 0, which means send the next packet as soon as the previous one responsed. (default 0)
        *args and **kwargs: And all the other arguments available in ping() except `seq`.

    Returns:
        Formatted ping results printed.
    """
    timeout = kwargs.get("timeout")
    src = kwargs.get("src")
    unit = kwargs.setdefault("unit", "ms")
    i = 0
    while i < count or count == 0:
        if interval > 0 and i > 0:
            time.sleep(interval)
        output_text = "ping '{}'".format(dest_addr)
        output_text += " from '{}'".format(src) if src else ""
        output_text += " ... "
        delay = ping(dest_addr, seq=i, *args, **kwargs)
        print(output_text, end="")
        if delay is None:
            print("Timeout > {}s".format(timeout) if timeout else "Timeout")
        elif delay is False:
            print("Error")
        else:
            print("{value}{unit}".format(value=int(delay), unit=unit))
        i += 1


def do_ping(target_ip):
    """
    批量ping测试
    """
    try:
        delay = ping(target_ip)

        if delay is None:
            # ping超时
            with open('LOG' + os.sep + 'Timeout_ping_result_' + LogTime + '.txt', 'a+') as f:
                f.writelines(''.join('%-20s%-20s' % (target_ip, '超时')) + os.linesep)
        elif delay is False:
            # ping错误
            with open('LOG' + os.sep + 'Error_ping_result_' + LogTime + '.txt', 'a+') as f:
                f.writelines(''.join('%-20s%-20s' % (target_ip, '错误')) + os.linesep)
        else:
            show_info(''.join('%-20s%-20s' % (target_ip, '成功')))
            # ping成功
            with open('LOG' + os.sep + 'Success_ping_result_' + LogTime + '.txt', 'a+') as f:
                f.writelines(''.join('%-20s%-20s' % (target_ip, '成功')) + os.linesep)



    except Exception as e: 
        show_info(e)

def get_ip_list(ip):
    """
    获取ip列表
    """
    net4 = ipaddress.ip_network(ip, False)
    temp = net4.hosts()
    ip_list = []
    i = 0
    for item in temp:
        ip_list.append(str(item))
        i +=1
    return ip_list


if __name__ == '__main__':
    freeze_support()
    LogTime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    start_time = datetime.now()

    #创建日志目录
    my_file = "LOG" + os.sep
    
    ArgRoot = os.path.dirname(os.path.abspath(sys.argv[0]))
    print(ArgRoot)
    os.chdir(ArgRoot)
    dirname = os.path.abspath(".")
    if not os.path.exists(my_file):
        os.makedirs(my_file) 

    print(dirname)

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
            ip_list = get_ip_list(ips)
            print("正在工作中，请稍等……")
            for ip in ip_list:
                pool.apply_async(do_ping, args=(ip,))

    pool.close()
    pool.join()

    end_time = datetime.now()
    print('All done.总花费时间{:0.2f}s.'.format((end_time - start_time).total_seconds()))
    time.sleep(60)