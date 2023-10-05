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

            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f"Порт {port_} открыт")
                return f"Порт {port_} открыт"
            else:
                return f"Порт {port_} закрыт"

        start_time = time.time()
        text_list = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            for port in popular_ports:
                t = executor.submit(syn_scan_, host, port)
                text_list.append(t)
        end_time = time.time()

        print(f"Программа выполнилась за {end_time - start_time} секунд")
        return "".join([t.result() + "\n" for t in text_list])
    except Exception as e:
        raise ScanErrorException(e)
