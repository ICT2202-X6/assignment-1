
#from geoip import geolite2
from scapy.all import *
from pprint import pprint
import sys
import pyshark
from base64 import urlsafe_b64encode
from virustotal_python import Virustotal


#file names from https://kc.mcafee.com/corporate/index?page=content&id=KB94571&locale=en_US
cobalt_list=['47.exe', "1901.bin", "1901s.bin", '2701.bin', "27012.bin", "0102.bin", "0102s.bin", "0902.bin", "0902s.bin",
             "fls.exe", "6fokjewkj.exe", "6gdwwv.exe", "6lavfdk.exe", "6yudfgh.exe"]

api_key = "1535becddc18e1fac97c7bdc8d8d2a0265d5f3be3646896b0c697b1cb38a6873"
vt = Virustotal(api_key, API_VERSION="v3")


def virus_total_checker():
    print("Enter the url you want checked ")
    urlstring = str(input())
    try:
        # Send URL to VirusTotal for analysis
        resp = vt.request("urls", data={"url": urlstring}, method="POST")
        # URL safe encode URL in base64 format
        # https://developers.virustotal.com/v3.0/reference#url
        url_id = urlsafe_b64encode(urlstring.encode()).decode().strip("=")
        # Obtain the analysis results for the URL using the url_id
        analysis_resp = vt.request(f"urls/{url_id}")
        domain_resp = vt.request(f"domains/{urlstring}")

        pprint(analysis_resp.object_type)
        pprint(analysis_resp.data)
        pprint(resp.data)

    except:
        print(f"An error occurred")
        print_menu()



def http_checker(pkt):
    try:
        if pkt.http:
            if pkt[pkt.transport_layer].srcport != 80 and pkt[pkt.transport_layer].srcport != 443 and pkt.http.host !="":
                print("Unusual HTTP Traffic")
                print("Infected IP:" + pkt.ip.src)
                print("Suspected URL: " + pkt.http.host)
                print("Communicating From:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("\n")

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass

# might want to include virus total api to check suspected URLs
def find_unusual_http():
    pyshark_cap.apply_on_packets(http_checker, timeout=100)
    print("Options:")
    print("1. Check URL against Virus Total Database (limit 4 per minute)")
    print("2. Exit")
    x = str(input())
    if x == "1":
        virus_total_checker()
    elif x == '2':
        print_menu()
    else:
        exit()


def malware_checker(pkt):
    try:
        if pkt.http.request_method == "GET":
            if pkt.http.request_uri in cobalt_list:
                print("Infected IP:" + pkt.ip.src)
                print("Communicating From:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("C2 Server:" + pkt.ip.dst)
                print("Time:" + str(pkt.sniff_time))
                print("Traffic Purpose: Possible Hancitor IP Check")
                print("\n")
    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass

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
                print("Communicating From Port Number:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("C2 Server:" + pkt.ip.dst)
                print("Time:" + str(pkt.sniff_time))
                print("Traffic Purpose: C2 Traffic")
                print("\n")
        if pkt.http.request_method == "GET":
            if "api.ipify.org" in pkt.http.host:
                print("Infected IP:" + pkt.ip.src)
                print("Communicating From Port Number:" + pkt[pkt.transport_layer].srcport)
                print("Malicious HTTP Request:" + pkt.http.request_uri)
                print("C2 Server:" + pkt.ip.dst)
                print("Time:" + str(pkt.sniff_time))
                print("Traffic Purpose: Possible Hancitor IP Check")
                print("\n")
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


def ip_location(ipadd):
    match = geolite2.lookup(ipadd)
    print(f"IP Address:{ipadd} , Country:{match.country}, Continent:{match.continent}")
    print_menu()


def find_ip_location(pcap):
    pprint(pcap.sessions())
    print("Please enter the IP address you would like the Location identified")
    x = input()
    ip_location(x, pcap)
    print("return to menu ? (y/n)")
    x = str(input())
    if x == 'y':
        print_menu()
    else:
        exit()


def help_description():
    print("\nOption 1 : Option 1 Description")
    print("Option 2 : Option 1 Description")
    print("Option 3 : Option 1 Description")
    print("Press 0 to return to menu")
    x = int(input())
    if x == 0:
        print_menu()


def print_menu():
    print("Packet Analysis:")
    print("Choose an Option:")
    print("1. View Sessions ")
    print("2. Check for LOKIBot IOCs ")
    print("3. Check for Hancitor Malware IOCs")
    print("4. Check for Unusual HTTP traffic")
    print("0. Help \n")
    menu(pcap_file)


def menu(pcap):
    x = int(input())
    if x == 1:
        find_ip_location(pcap)
    elif x == 2:
        find_Loki_packet()
    elif x == 3:
        find_Hancitor_packet()
    elif x == 4:
        find_unusual_http()
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
        print_menu()
    else:
        print("File does not exist")
