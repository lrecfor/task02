"""Module providing scanner functions."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
import re
import scapy
from scapy.layers.inet import IP, TCP, ICMP
from utils import ScanErrorException, IP_PATTERN


class Scanner:
    """Parent class for scanner functions."""

    def __init__(self, host, ports):
        self.host = host
        self.ports = ports

    @staticmethod
    def get_ip_by_domain_name(domain_name):
        """
        Returns the IP address by domain

        :param domain_name: domain name to get ip address for.
        """
        try:
            ip_address = socket.gethostbyname(domain_name)
            return ip_address
        except socket.herror:
            return "No domain name found"

    def scan(self, func):
        """
        Scanning ports by execute func with ThreadPoolExecutor.

        :func: function to execute with ThreadPoolExecutor
        :return: list of strings with result of scanning
        """
        try:
            start_time = time.time()
            text_list = []
            with ThreadPoolExecutor(max_workers=15) as executor:
                for port in self.ports:
                    text_list.append(executor.submit(func, self.host, port))
            end_time = time.time()

            print(f"Программа выполнилась за {end_time - start_time} секунд")
            return "".join([t.result() for t in text_list])
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text


class ACKScanner(Scanner):
    """Class for ack scanning"""

    def ack_scan(self):
        """
        Scan ports using ack packets by call scan() function.

        :return: list of strings with result of scanning
        """
        def ack_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="A")
            response = scapy.layers.inet.sr1(packet_, verbose=0, timeout=10)

            if response is None:
                return f"{port_:<{10}}\t\t{'Filtered'}\n"

            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x4:
                    return ""
                if response.getlayer(TCP).flags == 0x14:
                    return ""
            elif response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type) == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<{10}}\t{'Filtered'}\n"

            return ""

        if re.match(IP_PATTERN, self.host) is None:
            self.host = self.get_ip_by_domain_name(self.host)
        try:
            return self.scan(ack_scan_)
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text


class FINScanner(Scanner):
    """Class for fin scanning"""

    def fin_scan(self):
        """
        Scan ports using fin packets by call scan() function.

        :return: list of strings with result of scanning
        """
        def fin_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="F")
            response = scapy.layers.inet.sr1(packet_, verbose=0, timeout=10)

            if response is None:
                return f"{port_:<10}\t\tOpen/Filtered\n"

            if response:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    return ""
                if (response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<10}\t\tFiltered\n"

            return ""

        if re.match(IP_PATTERN, self.host) is None:
            self.host = self.get_ip_by_domain_name(self.host)
        try:
            return self.scan(fin_scan_)
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text


class NULLScanner(Scanner):
    """Class for null scanning"""

    def null_scan(self):
        """
        Scan ports using no packets by call scan() function.

        :return: list of strings with result of scanning
        """
        def null_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="")
            response = scapy.layers.inet.sr1(packet_, verbose=0, timeout=10)

            if response is None:
                return f"{port_:<{10}}\t\t{'Open|Filtered'}\n"

            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:
                    return ""
            elif response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type) == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<{10}}\t{'Filtered'}\n"

            return ""

        if re.match(IP_PATTERN, self.host) is None:
            self.host = self.get_ip_by_domain_name(self.host)
        try:
            return self.scan(null_scan_)
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text


class SYNScanner(Scanner):
    """Class for syn scanning"""

    def syn_scan(self):
        """
        Scan ports using syn packets by call scan() function.

        :return: list of strings with result of scanning
        """
        def syn_scan_(host_, port_):
            packet_ = IP(dst=host_) / TCP(dport=port_, flags="S")
            response = scapy.layers.inet.sr1(packet_, verbose=0, timeout=10)

            if response is None:
                return f"{port_:<{10}}\t\t{'Filtered'}\n"

            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    return f"{port_:<{10}}\t\t{'open'}\n"
                if response.getlayer(TCP).flags == 0x14:
                    return ""
            elif response.haslayer(ICMP):
                if (int(response.getlayer(ICMP).type) == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<{10}}\t{'Filtered'}\n"

            return ""

        if re.match(IP_PATTERN, self.host) is None:
            self.host = self.get_ip_by_domain_name(self.host)
        try:
            return self.scan(syn_scan_)
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text
