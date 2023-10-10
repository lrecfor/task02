from scapy.layers.inet import IP, TCP, ICMP
from utils import ScanErrorException, default_ports
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import time


# def tcp_scan(host, ports_):
#     try:
#         pass
#     except Exception as e:
#         raise ScanErrorException(e)
#
#
# def udp_scan(host, ports_):
#     try:
#         pass
#     except Exception as e:
#         raise ScanErrorException(e)


def fin_scan(host, ports_):
    try:
        def fin_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="F")
            response = sr1(packet_, verbose=0, timeout=10)

            if response is None:
                return f"{port_:<10}\t\tOpen/Filtered\n"

            elif response:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    return ""
                elif (response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and
                      int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<10}\t\tFiltered\n"

            return ""

        start_time = time.time()
        text_list = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            for port in ports_:
                text_list.append(executor.submit(fin_scan_, host, port))
        end_time = time.time()

        print(f"Программа выполнилась за {end_time - start_time} секунд")
        return "".join([t.result() for t in text_list])
    except Exception as e:
        print(e)
        raise ScanErrorException(e)


def syn_scan(host, ports_):
    try:
        def syn_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="S")
            response = sr1(packet_, verbose=0, timeout=0.5)

            if response is None:
                return f"{port_:<{10}}\t\t{'filtered'}\n"

            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    return f"{port_:<{10}}\t\t{'open'}\n"
                elif response.getlayer(TCP).flags == 0x14:
                    return ""
            elif response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type) == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<{10}}\t{'filtered'}\n"

            return ""

        start_time = time.time()
        text_list = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            for port in ports_:
                text_list.append(executor.submit(syn_scan_, host, port))
        end_time = time.time()

        print(f"Программа выполнилась за {end_time - start_time} секунд")
        return "".join([t.result() for t in text_list])
    except Exception as e:
        raise ScanErrorException(e)


def ack_scan(host, ports_):
    try:
        def ack_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="A")
            response = sr1(packet_, verbose=0, timeout=10)

            if response is None:
                return f"{port_:<{10}}\t\t{'filtered'}\n"

            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x4:
                    return ""   # f"{port_:<{10}}\t\t{'unfiltered'}\n"
                elif response.getlayer(TCP).flags == 0x14:
                    return ""
            elif response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type) == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<{10}}\t{'filtered'}\n"

            return ""

        start_time = time.time()
        text_list = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            for port in ports_:
                text_list.append(executor.submit(ack_scan_, host, port))
        end_time = time.time()

        print(f"Программа выполнилась за {end_time - start_time} секунд")
        return "".join([t.result() for t in text_list])
    except Exception as e:
        raise ScanErrorException(e)

