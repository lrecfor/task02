"""Module providing scanner functions."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
import re

import requests
import scapy
import socks
from scapy.layers.inet import IP, TCP, ICMP

from config import MAX_WORKERS, TIMEOUT, SOCKS_IP, SOCKS_PORT
from src.utils import ScanErrorException, GetIpByDomainNameErrorException, IP_PATTERN


class Scanner:
    """Parent class for PortScanner class."""

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
        except Exception as error:
            raise GetIpByDomainNameErrorException(error) from error

    def scan(self, func):
        """
        Scanning ports by execute func with ThreadPoolExecutor.

        :func: function to execute with ThreadPoolExecutor
        :return: list of strings with result of scanning
        """
        try:
            start_time = time.time()
            text_list = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                for port in self.ports:
                    text_list.append(executor.submit(func, self.host, port))
            end_time = time.time()

            print(f"Программа выполнилась за {end_time - start_time} секунд")
            return "".join([t.result() for t in text_list])
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text


class PortScanner(Scanner):
    """Class for port scanning."""

    def __init__(self, host, ports, flags):
        super().__init__(host, ports)
        self.flags = flags

    def port_scan(self):
        """Scanning ports by call scan() function with port_scan_() func as argument."""

        def port_scan_(host_, port_):
            """
            Scanning port. Sends a packet with the flag defined in self.flag.
            If port is open, then return "Open" string.
            If port is filtered, then return "Filtered" string.
            If the port was not accurately determined to be open or closed,
            returns "Open|Filtered" string.

            :return: string with result of scanning
            """
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, SOCKS_IP, SOCKS_PORT)
            socket.socket = socks.socksocket

            packet_ = IP(dst=host_) / TCP(dport=port_, flags=self.flags)
            response = scapy.layers.inet.sr1(packet_, verbose=0, timeout=TIMEOUT)

            if response is None:
                if self.flags in ('A', 'S'):
                    return f"{port_:<{10}}\t\t{'Filtered'}\n"
                if self.flags in ('F', ''):
                    return f"{port_:<{10}}\t\t{'Open|Filtered'}\n"

            if response:
                if (response.haslayer(TCP) and (
                        self.flags == "A" and response.getlayer(TCP).flags == 0x4) or (
                        response.getlayer(TCP).flags == 0x14)):
                    return ""
                if response.haslayer(TCP) and self.flags == "S" and response.getlayer(
                        TCP).flags == 0x12:
                    return f"{port_:<{10}}\t\t{'Open'}\n"
                if (response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and
                        int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return f"{port_:<{10}}\t\t{'Filtered'}\n"

            return ""

        try:
            if re.match(IP_PATTERN, self.host) is None:
                self.host = self.get_ip_by_domain_name(self.host)
        except GetIpByDomainNameErrorException as error_text:
            raise ScanErrorException(error_text) from error_text

        try:
            return self.scan(port_scan_)
        except Exception as error_text:
            raise ScanErrorException(error_text) from error_text


class ACKScanner(PortScanner):
    """
    Class for ack scanning. Scan ports using ack packets.
    """

    def __init__(self, host, ports):
        super().__init__(host, ports, "A")


class FINScanner(PortScanner):
    """
    Class for fin scanning. Scan ports using fin packets.
    """

    def __init__(self, host, ports):
        super().__init__(host, ports, "F")


class NULLScanner(PortScanner):
    """
    Class for null scanning. Scan ports using no packets.
    """

    def __init__(self, host, ports):
        super().__init__(host, ports, "")


class SYNScanner(PortScanner):
    """
    Class for syn scanning. Scan ports using syn packets.
    """

    def __init__(self, host, ports):
        super().__init__(host, ports, "S")
