# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

from geoip import geolite2
from scapy.all import *
import pprint
import sys
import pyshark


def find_tcp_packet(pcap):
    cap.apply_on_packets(Exfil, timeout=100)



def ip_location(ipadd, pcap):
    match = geolite2.lookup(ipadd)
    print(f"IP Address:{ipadd} , Country:{match.country}, Continent:{match.continent}")
    print_menu(pcap)


def find_ip_location(pcap):
    pprint.pprint(pcap.sessions())
    print("Please enter the IP address you would like the Location identified")
    x = input()
    ip_location(x, pcap)


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
    print("1. Identify Packet Location ")
    print("2. Check for LOKIBot IOCs ")
    print("0. Help \n")
    menu(pcap)


def menu(pcap):
    x = int(input())
    if x == 1:
        find_ip_location(pcap)
    elif x == 2:
        find_tcp_packet(pcap)
    elif x == 0:
        help_description(pcap)


# function to read pcap file
def load_pcap_file(pcap):
    pcap = rdpcap(pcap)
    return pcap


def Exfil(pkt):
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


if __name__ == '__main__':

    # taking cli argument for the path of the pcap file currently needs quotation marks for the filepath
    fileLocation = sys.argv[1]
    # Checking if the given file location is an actual file
    if os.path.isfile(fileLocation):
        cap= pyshark.FileCapture(fileLocation)
        # run the function that loads the pcap file
        pcap_file = load_pcap_file(fileLocation)
        # print menu
        print_menu(pcap_file)
        # prints number of TCP , UDP ,ICMP and Other packet types
        # print(pcap_file)
        # prints the information of the specific packet
        # packet = pcap_file[2000]
        # print(packet.__dict__)
        # print(packet.show())
        # print(packet.show2())

    else:
        print("File does not exist")
