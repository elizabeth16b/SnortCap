# Snort-Rule-Generator
Generate Snort rules based on the network traffic captured. The script will go through a pcap file and determine whether there any failed SSH Brute Force attempts. If the script determines that there is failed SSH Brute Force attempts, it will proceed to generate a new file in the /etc/snort/rules/ directory with suggested Snort rules pertaining to the traffic it detected. 

## Purpose
The purpose of this script is to add value to the cybersecurity team. The amount of time this scipt can save to find potential failed SSH Brute Force attampts in the network will not only increase the chances of adversary events like these going undetected, but will also be a huge game changer for the incident response team. 

## SSH Brute Force
SSH enables remote, encrypted access to any system running an SSH server. It requires user authentication. Since SSH traffic is encrypted, it is not easy to differentiate successful versus failed login attempts in Wireshark. However, some features of the traffic can help to reveal whether or not an attempted authentication is successful:


      SSH servers have set responses for successful and failed authentications. Observing the length of the SSH packets can show whether authentication       
      succeeded or failed. In Zeek, a server is assumed to send a 5 kB response to a login request if the authentication was successful.
      Check out more information at: https://resources.infosecinstitute.com/category/certifications-training/network-traffic-analysis-for-incident-
      response/how-to-use-traffic-analysis-for-wireshark/ssh-protocol-with-wireshark/
            
## Security Tools
1. Python
2. Snort
3. PCAP file

## Sample PCAP file
If you do not have a PCAP file with SSH Brute Force attempts in it, you can check Jon Siwek's github at https://github.com/jsiwekSide. There you will find a PCAP file you can use: 
https://github.com/bro/bro/raw/master/testing/btest/Traces/ssh/sshguess.pcap (use wget)

Note: This is considered version 1.0 of SnortCap. When working on this script I had a week to complete it, as a student in an intensive cybersecurity bootcamp. I enjoyed working on this script and learned way more than I did to begin with. You will see more refined versions of this script in the future
