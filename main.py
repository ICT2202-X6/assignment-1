# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

from geoip import geolite2
from scapy.all import *
import pprint
import sys
import pyshark

#file names from https://kc.mcafee.com/corporate/index?page=content&id=KB94571&locale=en_US
cobalt_list=['47.exe', "1901.bin", "1901s.bin", '2701.bin', "27012.bin", "0102.bin", "0102s.bin", "0902.bin", "0902s.bin",
             "fls.exe", "6fokjewkj.exe", "6gdwwv.exe", "6lavfdk.exe", "6yudfgh.exe"]


def malware_checker(pkt):
    if pkt.http.request_method == "GET":
        if cobalt_list in pkt.http.host:
            print("Infected IP:" + pkt.ip.src)
            print("Communicating From:" + pkt[pkt.transport_layer].srcport)
            print("Malicious HTTP Request:" + pkt.http.request_uri)
            print("C2 Server:" + pkt.ip.dst)
            print("Time:" + str(pkt.sniff_time))
            print("Traffic Purpose: Possible Hancitor IP Check")
            print("\n")


def find_Cobalt_packet():
    pyshark_cap.apply_on_packets(malware_checker, timeout=100)
    print("return to menu ? (y/n)")
    x = str(input())
    if x == 'y':
        print_menu()
    else:
        exit()


def hancitor_filter(pkt):
    # /8/forum.php as of 2020 all hancitor C2 traffic has ended with that.
    # Hancitor first causes an IP address check to api.ipify.org by the infected Windows host
    # Of note, traffic to api.ipify.org is an indicator, but it’s not inherently malicious by itself
    try:
        if pkt.http.request_method == "POST":
            if "/8/forum.php" in pkt.http.request_uri:
                print("Infected IP:" + pkt.ip.src)
                print("Communicating From:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("C2 Server:" + pkt.ip.dst)
                print("Time:" + str(pkt.sniff_time))
                print("Traffic Purpose: C2 Traffic")
                print("\n")
        if pkt.http.request_method == "GET":
            if "api.ipify.org" in pkt.http.host:
                print("Infected IP:" + pkt.ip.src)
                print("Communicating From:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("C2 Server:" + pkt.ip.dst)
                print("Time:" + str(pkt.sniff_time))
                print("Traffic Purpose: Possible Hancitor IP Check")
                print("\n")
        print("try")
    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


def find_Hancitor_packet():
    pyshark_cap.apply_on_packets(hancitor_filter, timeout=100)
    print("Check for Possible Cobalt Strike or Ficker Stealer installation by Hancitor ?(y/n)")
    x=str(input())
    if x == 'y':
        find_Cobalt_packet()
    else :
        print_menu()


def fil_loki(pkt):
    try:
        if pkt.http.request_method == "POST":
            if pkt.http.user_agent == "Mozilla/4.08 (Charon; Inferno)":
                print("Infected IP:" + pkt.ip.src)
                print("Communicating From:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("Malicious User-Agent" + pkt.http.user_agent)
                print("C2 Server:" + pkt.ip.dst)
                print("Time:" + str(pkt.sniff_time))
                Reason = pkt.http.data[4:6]
                if Reason == "27":
                    print("Traffic Purpose: Exfiltrate Application/Credential Data")
                elif Reason == "28":
                    print("Traffic Purpose: Get C2 Commands")
                elif Reason == "2b":
                    print ("Traffic Purpose': Exfiltrate Keylogger Data")
                elif Reason == "26":
                    print ("Traffic Purpose': Exfiltrate Cryptocurrency Wallet")
                elif Reason == "29":
                    print ("Traffic Purpose': Exfiltrate Files")
                elif Reason == "2a":
                    print ("Traffic Purpose': Exfiltrate POS Data")
                elif Reason == "2c":
                    print ("Traffic Purpose': Exfiltrate Screenshots")
                print ("\n")

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


def find_Loki_packet():
    pyshark_cap.apply_on_packets(fil_loki, timeout=100)
    print("return to menu ? (y/n)")
    x = str(input())
    if x == 'y':
        print_menu()
    else:
        exit()


def ip_location(ipadd, pcap):
    match = geolite2.lookup(ipadd)
    print(f"IP Address:{ipadd} , Country:{match.country}, Continent:{match.continent}")
    print_menu(pcap)


def find_ip_location(pcap):
    pprint.pprint(pcap.sessions())
    print("Please enter the IP address you would like the Location identified")
    x = input()
    ip_location(x, pcap)
    print("return to menu ? (y/n)")
    x = str(input())
    if x == 'y':
        print_menu()
    else:
        exit()


def help_description(pcap):
    print("\nOption 1 : Option 1 Description")
    print("Option 2 : Option 1 Description")
    print("Option 3 : Option 1 Description")
    print("Press 0 to return to menu")
    x = int(input())
    if x == 0:
        print_menu(pcap)


def print_menu(pcap):
    print("Packet Analysis:")
    print("Choose an Option:")
    print("1. View Sessions ")
    print("2. Check for LOKIBot IOCs ")
    print("3. Check for Hancitor Malware IOCs")
    print("0. Help \n")
    menu(pcap)


def menu(pcap):
    x = int(input())
    if x == 1:
        find_ip_location(pcap)
    elif x == 2:
        find_Loki_packet()
    elif x == 3:
        find_Hancitor_packet()
    elif x == 0:
        help_description(pcap)


# function to read pcap file
def load_pcap_file(pcap):
    pcap = rdpcap(pcap)
    return pcap


if __name__ == '__main__':

    # taking cli argument for the path of the pcap file currently needs quotation marks for the filepath
    fileLocation = sys.argv[1]
    # Checking if the given file location is an actual file
    if os.path.isfile(fileLocation):
        # run the function that loads the pcap file for pyshark
        pyshark_cap = pyshark.FileCapture(fileLocation)
        # run the function that loads the pcap file for scapy
        pcap_file = load_pcap_file(fileLocation)
        # print menu
        print_menu(pcap_file)


    else:
        print("File does not exist")
