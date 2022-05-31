from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
from scapy.layers.l2 import getmacbyip, Ether, ARP
from typing import *
from enum import Enum
from datetime import datetime

ENCODING = "utf-8"


class Mode(Enum):
    """
    Enum for the activation modes.
    """
    NONE = 0
    TIME = 1
    QUERY_TARGET = 2
    LETTER_MODE = 3


IFACE = ""
FILTER = "udp port 53 "  # && udp.srcport == dns.id && ip.id == dns.id"
ACTIVATION_MODE = Mode.LETTER_MODE
LEGIT_DNS_REQUESTS = ["www.google.com.", "www.facebook.com.", "www.cutedogs.com.", "www.youtube.com.",
                      "www.amazon.com.", "www.reddit.com.", "www.wikipedia.org.", "www.linkedin.com.",
                      "www.instagram.com.", "www.twitter.com.", "www.pinterest.com.", "www.tumblr.com.",
                      "www.quora.com.", "www.stackoverflow.com.", "www.github.com.", "www.moodle2.cs.huji.ac.il.", ]


def start_sniffing():
    """
    Starts sniffing on the interface.
    """
    sniff(filter=FILTER, iface=IFACE, prn=find_packets)


def handle_packet(pkt: Packet) -> None:
    """
    Handles the packet.
    """
    # pkt.show2() can be used for debugging purposes.
    handler = None
    if ACTIVATION_MODE == Mode.TIME:
        handler = handle_time_mode
    elif ACTIVATION_MODE == Mode.QUERY_TARGET:
        handler = handle_target_mode
    elif ACTIVATION_MODE == Mode.LETTER_MODE:
        handler = handle_letter_mode
    if handler != None:
        res = handler(pkt)
        if res:
            print(res, end="")


def is_marked(pkt: Packet) -> bool:
    """
    Checks if the packet is marked.
    """
    if pkt[IP].id == pkt[DNS].id and pkt[DNS].id == pkt[UDP].sport:
        return True
    return False


def find_packets(pkt: Packet) -> None:
    """
    Finds all marked packets and sends them to handle_packet.
    """
    if is_marked(pkt):
        handle_packet(pkt)


def handle_time_mode(pkt: Packet) -> int:
    """
        Handles the time mode.
        @ param pkt The packet to handle.
        @ return The received data
    """
    return datetime.now().minute  # TODO: aa


def handle_target_mode(pkt: Packet) -> int:
    """
        Handles the target mode. 
        Returns -1 if target is not in the list
        @ param pkt The packet to handle.
        @ return The received data
    """
    try:
        return LEGIT_DNS_REQUESTS.index(pkt[DNSQR].qname.decode(ENCODING))
    except ValueError:
        return -1


def handle_letter_mode(pkt: Packet) -> str:
    """
        Handles the letter mode.
        @ param pkt The packet to handle.
        @ return The received data
    """
    num = handle_target_mode(pkt)
    handle_letter_mode.buffer.append("{0:04b}".format(num))
    if len(handle_letter_mode.buffer) == 2:
        ans_num = int("".join(handle_letter_mode.buffer), 2)
        handle_letter_mode.buffer.clear()
        return chr(ans_num)
    return ""


handle_letter_mode.buffer = []


if __name__ == '__main__':
    start_sniffing()
