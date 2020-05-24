#!/usr/bin/env python
import scapy.all as scapy
import nmap

arpLayer = scapy.ARP

scanner = nmap.PortScanner()
def getMac(ip):
    scanner.scan(ip, arguments="-T4 -F")
    if not ip:
        print("[-] No IP has been submitted")
        quit()
    # if not "mac" in scanner[ip]["addresses"]:
    #     print("[-] There is no existing MAC for that IP Address")
    #     quit()
    else:
        ip_MAC = scanner[ip]["addresses"]["mac"]
        if not ip_MAC:
            print("[-] There is no MAC address for that host, that or there is no such host")
        else:
            return ip_MAC

def processPacket(packet):
    try:
        if packet.haslayer(arpLayer) and packet[arpLayer].op == 2:
            real_mac = getMac(packet[arpLayer].psrc)
            response_mac = packet[arpLayer].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack, the attack is from {}".format(response_mac))
    except IndexError:
        pass

def sniff(interface):
    scapy.sniff(iface=interface, prn=processPacket, store=False)

sniff("wlan0")