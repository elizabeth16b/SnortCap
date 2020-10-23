#!/usr/bin/env python3

#import necessary modules
from scapy.all import *
import sys
import os

#Arguments that the file will take
pcap_file = sys.argv[1]
pcap = rdpcap(pcap_file)

#Color scheme
W  = '\033[0m'  # white 
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple

#add generated snort rules to a new file in the /etc/snort/rules/ directory andread afterwards, if a file by that name already exists, just read the file
def create_file(): 
    if os.path.isfile('/etc/snort/rules/SnortCap_file.rules') == False: 
        f = open('/etc/snort/rules/SnortCap_file.rules', 'x')
        f = open('/etc/snort/rules/SnortCap_file.rules', 'w') 
        f.write(G + '-----------------------------------------------------------------------------\n')
        f.write(B + 'Suggested Snort rules based off of the SSH Brute Force Attempts detected\nin your network traffic:\n')
        f.write(G + '-----------------------------------------------------------------------------\n')

#https://ecs.wgtn.ac.nz/foswiki/pub/Courses/CYBR371_2020T1/Labs/Lab4.pdf
        f.write(B + '\nBLEEDING-EDGE POTENTIAL SSH SCAN\n')
        f.write(W + '[ 1 ] This rule tells your snort to generate an alert every time it detects a TCP SSH protocol dictionary attacks. Snort checks the packets for tcp protocol from an external source on any ports directed at our home subnet, received on port 22. The packet header should also have a SYN flag (as identified by flags:S), and be captured 5 times during a 120 seconds period from the same source address. The packet is then classified as SSH bruteforce attack and the message“BLEEDING-EDGE Potential SSH Scan” is raised. You can find more information at' + B + ' https://ecs.wgtn.ac.nx/foswiki/pub/Courses/CYBR371_2020T1/Labs/Lab4.pdf\n' + G + '\nalert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BLEEDING-EDGE Potential SSH Scan"; flags:S; threshold:type threshold, track by_src, count 5, seconds 120; flowbits:set,ssh.brute.attempt;classtype:attempted-dos; sid:2001219; rev:8;)\n\n' + R + '----------' + '\n')
#https://seclists.org/snort/2012/q2/121
        f.write(B + '\nSSH BRUTE FORCE LOGIN ATTEMPT\n')
        f.write(W + '[ 2 ] An SSH brute force login attempt that was captured 5 times in 60 seconds. You can find more information at' + B + ' https://seclists.org/snort/2012/q2/121\n\n' + G + 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"BAD-TRAFFIC SSH brute force login attempt"; flow:to_server,established; content:"SSH-"; depth:4;detection_filter:track by_src, count 5, seconds 60;classtype:misc-activity; sid:19559; rev:2;)\n\n' + R + '----------\n') 
#https://stackoverflow.com/questions/47742405/using-snort-suricata-i-want-to-generate-an-ssh-alert-for-every-failed-login-to
        f.write(B + '\nSSH BRUTE FORCE ATTEMPT - EXTERNAL TO INTERNAL\n')
        f.write(W + '[ 3 ] This is a possible SSH brute force attempt captured 5 times within 30 second from the external network to the internal network. You can find more information at' + B + ' https://stackoverflow.com/questions/47742405/using-snort-suricata-i-want-to-generate-an-ssh-alert-for-every-failed-login-to' + G + '\n\nalert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH brute forcing!"; flags: S+; threshold: type both, track by_src, count 5, seconds 30; sid:10000001; rev: 1;)\n\n' + R + '----------' + '\n')

#https://wiki.apnictraining.net/_media/sectutorial/05-2_ids_lab_answer.rtf
        f.write(B + '\nSSH BRUTE FORCE ATTACK - THRESHOLD\n')
        f.write(W + '[ 4 ] A rule to check SSH brute force attack and log IP trying to connect more than 3 times in 60 seconds. You can find more information at ' + B + 'https://wiki.apnictraining.net/_media/sectutorial/05-2_ids_lab_answer.rtf\n\n' + G + 'alert tcp any any -> $HOME_NET 22 (msg:"Potential SSH Brute Force Attack"; flow:to_server; flags:S; threshold:type threshold, track by_src, count 3, seconds 60; classtype:attempted-dos; sid:4; rev:1; resp:rst_all;)\n\n' + R + '----------' + '\n')

        f.write('\n')
        file_contents_created = f.read()
        print(file_contents_created)
        f.close()   
    else:
        f = open('/etc/snort/rules/SnortCap_file.rules', 'r') #
        file_contents = f.read()
        print(file_contents)
        f.close()

#looking at the packet size - if the bytes in the packet size that the server sends back to the client is less than 5kb it is considered a failed SSH Brute Force attempt and we will generate snort rules (https://resources.infosecinstitute.com/category/certifications-training/network-traffic-analysis-for-incident-response/how-to-use-traffic-analysis-for-wireshark/ssh-protocol-with-wireshark/)
def sshbf_detect():
    sessions = pcap.sessions()
    flag = False
    for session in sessions:
        if not flag:
            for packet in sessions[session]:
                try:
                    payload = bytes(packet[TCP].payload)
                    if packet[TCP].sport == 22 and len(payload) < 5000:
                        create_file()
                        flag = True
                        break
                except:
                    pass

    if flag == False:
         print (O + "\n\t\t\t\t\t||| SNORTCAP v1.0 |||")
         print (W + "\n This script parses a PCAP file and outputs useable Snort rule(s) based on the traffic captured")
         print (G + "\n\t\t\t\t\t    REQUIREMENTS:")
         print (W + "\t\t\t\t\t   -Python 3")
         print (W + "\t\t\t\t\t   -Snort") 
         print (W + "\t\t\t\t\t   -PCAP file")

         print (R + "\n\t\t\t\t\t\tUSAGE:")
         print (W + "\t\t\t\t SnortCap.py <pcap>")

sshbf_detect()

