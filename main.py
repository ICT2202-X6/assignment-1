# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os.path
import re
import sys
import scapy
from geoip import geolite2
from scapy.all import *
import pprint
from io import StringIO


packet_queue = defaultdict(list)
parsed_payload = {'Network': {}, 'Compromised Host/User Description': {}, 'Compromised Host/User Data': {},
                  'Malware Artifacts/IOCs': {}}


def format_header(unformatted_http_header):
    http_header_dict = {}
    split_http_header = unformatted_http_header.split(b'\r\n')
    s = split_http_header[0].decode()
    if s.startswith('POST '):
        method, URI, HTTPVersion = split_http_header.pop(0).split(b' ')

    http_header_dict['HTTP-Method'] = method
    http_header_dict['HTTP-URI'] = URI
    http_header_dict['HTTP-Version'] = HTTPVersion

    for header in split_http_header:
        x = ":"
        x = x.encode('utf_8')
        if x in header:
            key, value = header.split(b': ', 1)
            http_header_dict[key] = value

    return http_header_dict


def extractHeaderAndPayload(full_session):
    http_header = {}
    http_payload = StringIO()

    for packet in full_session:
        if packet[TCP].flags in (24, 25):
            p = packet[TCP].load.decode('ANSI')
            if p.startswith('POST '):
                http_header = format_header(packet[TCP].load)
            else:
                if Padding in packet:
                    http_payload = StringIO(packet[TCP].load + packet[Padding].load)
                else:
                    http_payload = StringIO(packet[TCP].load.decode('ANSI'))
    return http_header, http_payload


def isLokiBotTraffic(http_headers):
    indicator_count = 0
    content_key_pattern = re.compile("^([A-Z0-9]{8}$)")
    if 'User-Agent' in http_headers and http_headers['User-Agent'] == 'Mozilla/4.08 (Charon; Inferno)':
        return True
    if 'HTTP-Method' in http_headers and http_headers['HTTP-Method'] == 'POST':
        indicator_count += 1
    if all(key in http_headers for key in
           ('User-Agent', 'Host', 'Accept', 'Content-Type', 'Content-Encoding', 'Content-Key')):
        indicator_count += 1
    if 'User-Agent' in http_headers and any(
            UAS_String in http_headers['User-Agent'] for UAS_String in ('Charon', 'Inferno')):
        indicator_count += 1
    if 'Content-Key' in http_headers and content_key_pattern.match(http_headers['Content-Key']):
        indicator_count += 1

    if indicator_count >= 3:
        return True
    else:
        return False


def isCompletedSession(packet):
    pack__name = '%s:%s --> %s' % (packet[IP].src, packet[IP].sport, packet[IP].dst)
    packet_queue[pack__name].append(packet)
    for session in packet_queue:
        SYN = False
        PSH_ACK = False
        ACK_FIN = False
        PSH_ACK_FIN = False
        for sp in packet_queue[session]:
            if sp[TCP].flags == 2:
                SYN = True
            if sp[TCP].flags == 24:
                PSH_ACK = True
            if sp[TCP].flags == 17:
                ACK_FIN = True
            if sp[TCP].flags == 25:
                PSH_ACK_FIN = True
            if (SYN and PSH_ACK and ACK_FIN) or PSH_ACK_FIN:
                return True
        return False


def process_packets(packet):
    packet_key_name = '%s:%s --> %s' % (packet[IP].src, packet[IP].sport, packet[IP].dst)
    if isCompletedSession(packet):
        http_header, http_payload = extractHeaderAndPayload(packet_queue[packet_key_name])

        if isLokiBotTraffic(http_header):
            parsed_payload['Network'].update({'Source IP': packet[IP].src})
            parsed_payload['Network'].update({'Source Port': packet[IP].sport})
            parsed_payload['Network'].update({'Destination IP': packet[IP].dst})
            parsed_payload['Network'].update({'Destination Port': packet[IP].dport})
            parsed_payload['Network'].update({'HTTP URI': http_header['HTTP-URI']})
            parsed_payload['Network'].update({'HTTP Method': http_header['HTTP-Method']})
            parsed_payload['Network'].update({'Destination Host': http_header['Host']})
            parsed_payload['Network'].update(
                {'Data Transmission Time': datetime.fromtimestamp(packet.time).isoformat()})

            parsed_payload['Malware Artifacts/IOCs'].update({'User-Agent String': http_header['User-Agent']})
            parsed_payload['Network'].clear()
            parsed_payload['Compromised Host/User Description'].clear()
            parsed_payload['Compromised Host/User Data'].clear()
            parsed_payload['Malware Artifacts/IOCs'].clear()
        del packet_queue[packet_key_name]


def find_tcp_packet(pcap):
    for packet in pcap:
        if TCP in packet:
            process_packets(packet)


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


if __name__ == '__main__':

    # taking cli argument for the path of the pcap file currently needs quotation marks for the filepath
    fileLocation = sys.argv[1]
    # Checking if the given file location is an actual file
    if os.path.isfile(fileLocation):
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
