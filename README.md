# Snort-Rule-Generator
Generate Snort rules based on the network traffic captured. The script will go through a pcap file and determine whether there any failed SSH Brute Force attempts. If the script determines that there is failed SSH Brute Force attempts, it will proceed to generate a new file in the /etc/snort/rules/ directory with suggested Snort rules pertaining to the traffic it detected. 

## SSH Brute Force
SSH enables remote, encrypted access to any system running an SSH server. It requires user authentication. Since SSH traffic is encrypted, it is not easy to differentiate successful versus failed login attempts in Wireshark. However, some features of the traffic can help to reveal whether or not an attempted authentication is successful:
      SSH servers have set responses for successful and failed authentications. Observing the length of the SSH packets can show whether authentication       
      succeeded or failed. In Zeek, a server is assumed to send a 5 kB response to a login request if the authentication was successful.
            Check out more information at: https://resources.infosecinstitute.com/category/certifications-training/network-traffic-analysis-for-incident-response/how-to-use-traffic-analysis-for-wireshark/ssh-protocol-with-wireshark/
            
                  Side Note: This is considered version 1.0. When working on this script I had a week to complete it and learned more than I did to begin with.                              You will see more refined versions of this script in the future.
