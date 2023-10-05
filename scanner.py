from scapy.layers.inet import ICMP, IP, TCP, sr1
import socket
import struct
from datetime import datetime
from utils import ScanErrorException
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import time
import os

with open("ports.txt", "r") as f:
    popular_ports = f.readlines()
for i in range(len(popular_ports)):
    popular_ports[i] = int(popular_ports[i].replace("\n", ""))


def tcp_scan(host):
    try:
        pass
    except Exception as e:
        raise ScanErrorException(e)


def udp_scan(host):
    try:
        pass
    except Exception as e:
        raise ScanErrorException(e)


def fin_scan(host):
    try:
        pass
    except Exception as e:
        raise ScanErrorException(e)


def syn_scan(host):
    try:
        def syn_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="S")
            response = sr1(packet_, verbose=0, timeout=0.5)

            """ 
            for display all ports status 
            """
            # if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            #     print(f"Порт {port_} открыт")
            #     return str('''<font color="green">Порт ''' + str(port_) + ''' открыт</font><br>''')
            # else:
            #     return str('''<font color="red">Порт ''' + str(port_) + ''' закрыт</font><br>''')

            """ 
            for display only open ports 
            """
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                return f"{port_}\t\topen\n"
            else:
                return ""

        start_time = time.time()
        text_list = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            for port in popular_ports:
                text_list.append(executor.submit(syn_scan_, host, port))
        end_time = time.time()

        print(f"Программа выполнилась за {end_time - start_time} секунд")
        return "".join([t.result() for t in text_list])
    except Exception as e:
        raise ScanErrorException(e)
