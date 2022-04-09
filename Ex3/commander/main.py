from commander.sender import send_payload
import base64


def main():
    """
    Main function for commander
    """
    payload = b"print('Hello World!')\nprint(os.listdir())\n"
    output = send_payload(payload)
    print(output.decode('utf-8'))  # Should print Hello World!

