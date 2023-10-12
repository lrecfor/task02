from scapy.layers.inet import IP, TCP, ICMP
from utils import ScanErrorException
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import time
import socket


class Scanner:

    @staticmethod
    def get_domain_name(ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except socket.herror:
            return "No domain name found"

    @staticmethod
    def scan(host, ports_, func):
        """
        Scanning ports by execute func with ThreadPoolExecutor.

        :param host: host ip or domain name to scan
        :param ports_: list of ports to scan
        :param func: function to execute with ThreadPoolExecutor
        :return: list of strings with result of scanning
        """
        try:
            start_time = time.time()
            text_list = []
            with ThreadPoolExecutor(max_workers=15) as executor:
                for port in ports_:
                    text_list.append(executor.submit(func, host, port))
            end_time = time.time()

            print(f"Программа выполнилась за {end_time - start_time} секунд")
            return "".join([t.result() for t in text_list])
        except Exception as e:
            raise ScanErrorException(e)

    def ack_scan(self, host, ports_):
        """
        Scan ports using ack packets by call scan() function.

        :param host: host ip or domain name to scan
        :param ports_: list of ports to scan
        :return: list of strings with result of scanning
        """
        try:
            socket.inet_aton(host)
        except socket.error:
            host = self.get_domain_name(host)
        try:
            def ack_scan_(host_, port_):
                packet_ = IP(dst=host_) / TCP(dport=port_, flags="A")
                response = sr1(packet_, verbose=0, timeout=10)

                if response is None:
                    return f"{port_:<{10}}\t\t{'Filtered'}\n"

                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x4:
                        return ""  # f"{port_:<{10}}\t\t{'unfiltered'}\n"
                    elif response.getlayer(TCP).flags == 0x14:
                        return ""
                elif response.haslayer(ICMP):
                    if (int(response.getlayer(ICMP).type) == 3 and
                            int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                        return f"{port_:<{10}}\t{'Filtered'}\n"

                return ""

            return self.scan(host, ports_, ack_scan_)
        except Exception as e:
            raise ScanErrorException(e)

    def fin_scan(self, host, ports_):
        """
        Scan ports using fin packets by call scan() function.

        :param host: host ip or domain name to scan
        :param ports_: list of ports to scan
        :return: list of strings with result of scanning
        """
        try:
            socket.inet_aton(host)
        except socket.error:
            host = self.get_domain_name(host)
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

            return self.scan(host, ports_, fin_scan_)
        except Exception as e:
            raise ScanErrorException(e)

    def syn_scan(self, host, ports_):
        """
        Scan ports using syn packets by call scan() function.

        :param host: host ip or domain name to scan
        :param ports_: list of ports to scan
        :return: list of strings with result of scanning
        """
        try:
            socket.inet_aton(host)
        except socket.error:
            host = self.get_domain_name(host)
        try:
            def syn_scan_(host_, port_):
                packet_ = IP(dst=host_) / TCP(dport=port_, flags="S")
                response = sr1(packet_, verbose=0, timeout=10)

                if response is None:
                    return f"{port_:<{10}}\t\t{'Filtered'}\n"

                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        return f"{port_:<{10}}\t\t{'open'}\n"
                    elif response.getlayer(TCP).flags == 0x14:
                        return ""
                elif response.haslayer(ICMP):
                    if (int(response.getlayer(ICMP).type) == 3 and
                            int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                        return f"{port_:<{10}}\t{'Filtered'}\n"

                return ""

            return self.scan(host, ports_, syn_scan_)
        except Exception as e:
            raise ScanErrorException(e)
