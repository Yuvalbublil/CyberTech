from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
from scapy.layers.l2 import getmacbyip, Ether, ARP
import numpy as np
from typing import *
from datetime import datetime
from time import sleep

ENCODING = "utf-8"

Minutes_in_hour = 60

MAX_RANDOM_NUMBER = 1000

TARGET_SERVER = "8.8.8.8"
LEGIT_DNS_REQUESTS = ["www.google.com.", "www.facebook.com.", "www.cutedogs.com.", "www.youtube.com.",
                      "www.amazon.com.", "www.reddit.com.", "www.wikipedia.org.", "www.linkedin.com.",
                      "www.instagram.com.", "www.twitter.com.", "www.pinterest.com.", "www.tumblr.com.",
                      "www.quora.com.", "www.stackoverflow.com.", "www.github.com.", "www.moodle2.cs.huji.ac.il.", ]
CACHE_TIME = 60  # In seconds
CACHE_TIME = 3  # In seconds

DATA_TIME_LOWER_BOUND = 0
DATA_TIME_UPPER_BOUND = 31
DATA_TARGET_LOWER_BOUND = 0
DATA_TARGET_UPPER_BOUND = 15


def mark_packet(pkt: Packet) -> Packet:
    """
        Marks the packet so our sniffer can find it.
        Generates a random short x, and sets:
        - IP.id = x
        - UDP.sport = x
        - DNS.id = x 

        @param pkt packet to mark.
        @return pkt marked.
    """
    x = int(np.random.random() * MAX_RANDOM_NUMBER)
    pkt[IP].id = x
    pkt[DNS].id = x
    pkt[UDP].sport = x
    return pkt


def send_data_time(data: int) -> None:
    """
        This function sends out the given data using the protocol described
         in the first step of the exercise.
        The function makes sure that the data is within the allowed range,
         and sends it at the correct time.

        @param data data to send.
        @return None
    """
    if data > DATA_TIME_UPPER_BOUND or data < DATA_TIME_LOWER_BOUND:
        raise ValueError("date time data out of bound")
    now = datetime.now()
    end_of_min = False
    if now.second < Minutes_in_hour / 2:
        end_of_min = True
    delta = ((data - now.minute) * Minutes_in_hour - end_of_min * (Minutes_in_hour / 2)) % (Minutes_in_hour ** 2)
    print(f"waiting {delta} seconds for data: {data}")
    sleep(delta)
    print(f"sent{data}")
    dns_req = IP(dst=TARGET_SERVER) \
              / UDP(dport=53) \
              / DNS(rd=1, qd=DNSQR(qname=LEGIT_DNS_REQUESTS[np.random.random(len(LEGIT_DNS_REQUESTS))]))
    send(mark_packet(dns_req), verbose=0)


def send_data_target(data: int) -> None:
    """
        This function sends out the given data using the protocol described
         in the second step of the exercise.
        The function makes sure that the data is within the allowed range,
         and sends it, it then sleeps CACHE_TIME seconds.

        @param data data to send.
        @return None
    """
    if data > DATA_TARGET_UPPER_BOUND or data < DATA_TARGET_LOWER_BOUND:
        raise ValueError("target data out of bound")

    dns_req = IP(dst=TARGET_SERVER) \
              / UDP(dport=53) \
              / DNS(rd=1, qd=DNSQR(qname=LEGIT_DNS_REQUESTS[data]))
    s = mark_packet(dns_req)
    # s.show()
    send(s, verbose=0)
    sleep(CACHE_TIME)


def send_letter(letter: bytes) -> None:
    """
        This function sends out the given letter using the protocol described
         in the third step of the exercise.
        The function makes sure that the letter is online one charecter long

        @param letter letter to send.
        @return None
    """
    x = ord(letter.decode(ENCODING))
    binary = "{0:08b}".format(x)
    arr = [binary[:4], binary[4:]]
    for a in arr:
        send_data_target(int(a, 2))


def send_bytes(data: bytes) -> None:
    """
        This function sends out the given bytes using the protocol described
         in the fourth step of the exercise.

        @param data bytes to send.
        @return None
    """
    for i in range(len(data)):
        send_letter(data[i].to_bytes(1, byteorder='big'))


if __name__ == '__main__':
    send_bytes("hello".encode(ENCODING))
