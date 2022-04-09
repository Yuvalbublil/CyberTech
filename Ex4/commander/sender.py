from .settings import PORTS, COMMAND_PORT, IP

def send_payload(data: bytes)-> bytes:
    """
        This function performs the port knocking, it then connects to the COMMAND_PORT and sends the payload.
        The response is then returned.
    """
    pass