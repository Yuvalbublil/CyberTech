import time

from commander.settings import PORTS, COMMAND_PORT, IP
import socket
import pydivert

BUFSIZE = 4096
HOST = "127.0.0.1"


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def send_payload(data: bytes) -> bytes:
    """
        This function performs the port knocking, it then connects to the COMMAND_PORT and sends the payload.
        The response is then returned.
    """
    port_knock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in PORTS:
        port_knock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port_knock.sendto(bytes("just ignore me i'm just walking here", 'utf-8'), (IP, port))
        time.sleep(0.2)
    port_knock.sendto(int_to_bytes(len(data)), (IP, COMMAND_PORT))
    port_knock.sendto(data, (IP, COMMAND_PORT))
    size = int_from_bytes(port_knock.recvfrom(BUFSIZE)[0])
    received = 0
    rec_data = bytearray()
    while received < size:
        data, _ = port_knock.recvfrom(BUFSIZE)
        rec_data += data
        received = len(rec_data)
    return rec_data
