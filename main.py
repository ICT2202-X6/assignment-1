# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os.path
import sys
from scapy.all import *


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# function to read pcap file
def load_pcap_file(pcap):
    pcap = rdpcap(pcap)
    return pcap


if __name__ == '__main__':

    # taking cli argument for the path of the pcap file currently needs quotation marks for the filepath
    fileLocation = sys.argv[1]
    # Checking if the given file location is an actual file
    if os.path.isfile(fileLocation):
        pcap_file = load_pcap_file(fileLocation)
        # prints number of TCP , UDP ,ICMP and Other packet types
        print(pcap_file)
        # prints the information of the specific packet
        packet = pcap_file[2000]
        print(packet)
        print(ls(packet))
        print(packet.show())
        print(packet.summary())
    else:
        print("File does not exist")
