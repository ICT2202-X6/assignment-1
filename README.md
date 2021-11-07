# PCAP Analyzer

PCAP Analyzer is a tool used to gather interesting information from the give pcap file. It was made as an Assignment for Module 2202 Digital Forensics from the Singapore Institute of Technology.

Video demostration of our tool here: https://youtu.be/x6BxVM3tXOo

## Requirements
This tool was made in python3 and it is not recommended to be used in python 2.
This tool requires the following libraries installed to function, Scapy, Pyshark, PPrint and Virustotal-python.

Scapy: `pip3 install scapy`  
Pyshark: `pip3 install pyshark`  
PPrint: `pip3 install pprintpp`  
VirusTotal-Python: `pip3 install virustotal-python`   
Python Graphics Package: `pip3 install PyX==0.15`  
Python PDF Toolkit: `pip3 install  PyPDF2`  
texlive-binaries to be installed on linux:`apt install texlive-latex-base`


## Options 
### 1. Session Display
This option displays all the sessions in the pcap file along with its statistics like the number of packets, whether it is TCP or UDP. This allows users to have a quick overview of the pcap file and see if any particular session is of interest. 

### 2. LOKIBot Indicators Of Compromise 
LokiBot is a trojan malware that is commonly used by malicious actors used to steal information from victims. This malware is considered one of the most common trojans still in use today. This option of the tool, goes through pcap file and tries to identify as many malicious packets that originate from the LokiBot infected device. This tool identifies the malicious traffic through the User Agent that is associated to this malware `Mozilla/4.08 (Charon; Inferno)`. 

### 3. Hancitor Indicators of Compromise 
Hancitor is another very commonly used trojan that is used to load other malware onto victims devices. This tool is able to go through the pcap file and analyse traffic to identify possible hancitor packets. If such traffic is found, it will further allow the user to check for any possible malware downloads. This is done by checking first for the hancitor signature ( as of 2020, most hancitor malware follow this signature), which is the presense of `/8/forum.php` in the url request header as well as any packets sent to this host `api.ipify.org`. Together, these form really good indicators of compromise. Then the tool can check for any installations of colbalt strike or ficker stealer. It does this by comparing a list of known malicious exe and bin file names gathered from reputable sources. 

### 4. Unusual HTTP Activity 
Plenty of malware avoid common signatures, which makes it hard to confirm whether traffic is malicious or not, however, there are malwares that use web traffic for malicious purposes but do so using non standard port numbers. This tool filters the pcap file for such traffic. We can then further compare the url with virus total's database and check if it is a known malicious url. The api used is for a free account that only allows for 4 url checks per minute. 

### 5. Sniffing
This options allows the user to sniff packets on their current network interface. It then creates a readable pdf file that helps to assist in explaining the contents of the what the sniffed data means. Alongside that, it creates a pcap file for each sniffing session allowing it to be used against the other four features mentioned above.

### Warning
The pcap files included in this github page, contain malware. It is recommended that if this script is to be used that it should be in a safe and isolated environment like a Linux Virtual Machine. The password for the zip file is "infected". The pcap files are sourced from R3MRUM github page for the Loki traffic and Palo Alto's Unit 42 Github for the Hancitor Traffic.

## Instructions 
Running the analyzer without any arguments will launch to a menu that only gives the option to load a pcap file or go straight to the sniffing feature.
`python3 analyzer.py`  
![image](https://user-images.githubusercontent.com/22877622/140532206-d41e5cd9-1706-43f2-b1f6-ace8495c3bc9.png)

with the file location as an argument, the tool will present the full featured menu
`python3 analyzer.py file.pcap` 
![image](https://user-images.githubusercontent.com/22877622/140531953-b6c683d1-db00-45c3-8d63-e603aa56b16b.png)


## Troubleshooting

For the Sniffing option, the tool has to be run as root.  
Python modules are installed in the user home directory, when you run scripts as root, you must ensure that the root user has those modules installed as well.
