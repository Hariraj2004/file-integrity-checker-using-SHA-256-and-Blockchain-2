import uuid
import socket
import psutil
import getpass

def get_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
    return mac.upper()

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_hostname():
    return socket.gethostname()

def get_username():
    try:
        return getpass.getuser()
    except Exception:
        return "Unknown"

def get_system_identity():
    return {
        "mac_address": get_mac_address(),
        "ip_address": get_ip_address(),
        "hostname": get_hostname(),
        "username": get_username()
    }
