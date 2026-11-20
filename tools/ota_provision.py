#!/usr/bin/env python3
"""G16B: provision the Guardian's UPDATE-mode Wi-Fi and Mac server URL over USB serial.

    tools/ota_provision.py --port /dev/cu.usbmodemXXXX [--url http://<mac-ip>:8070]

Asks for the owner's SSID and password (password via getpass, never echoed) and sends
them hex-encoded with the server URL to the device, which stores them in NVS. Neither
this tool nor the device ever prints the SSID, password or URL; only acknowledgements
("OTA ACK ...", "OTA SAVED ...", "OTA provisioned=yes ...") are shown. The Guardian
joins this network only inside an owner-confirmed UPDATE (both keys ~3 s + FRONT=yes).
`--clear` removes the stored values. Nothing here flashes or reboots the device.
"""
import argparse, getpass, socket, sys, time


def lan_ip():
    """This Mac's address on the default route (no packet is sent by a UDP connect)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('192.0.2.1', 9))   # TEST-NET-1: route lookup only
        return s.getsockname()[0]


def commands(ssid, password, url):
    """The console lines for one provisioning; values are hex-encoded (never printed)."""
    if not 1 <= len(ssid.encode()) <= 32:
        raise ValueError('SSID must be 1..32 bytes')
    if password and not (8 <= len(password) <= 63 and password.isascii() and password.isprintable()):
        raise ValueError('password must be 8..63 printable ASCII characters (or empty for an open network)')
    if not url.startswith('http://') or len(url) > 120 or any(c <= ' ' or c > '~' for c in url):
        raise ValueError('URL must be http://host[:port][/path], printable, at most 120 characters')
    return [f'OTA SSID {ssid.encode().hex()}', f'OTA PASS {password.encode().hex() if password else "-"}',
            f'OTA URL {url}', 'OTA SAVE', 'OTA?']


def exchange(port, lines, timeout=3.0):
    import serial   # pyserial (present in the ESP-IDF Python environment)
    replies = []
    with serial.Serial(port, 115200, timeout=0.2) as link:
        time.sleep(0.3); link.reset_input_buffer()
        for line in lines:
            link.write((line + '\n').encode())
            deadline = time.time() + timeout
            while time.time() < deadline:
                text = link.readline().decode(errors='replace').strip()
                if text.startswith('OTA '):   # device replies never contain the values
                    replies.append(text); break
            else:
                replies.append('OTA (no reply)')
    return replies


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--port', required=True, help='the identified Guardian USB serial port')
    p.add_argument('--url', help='server URL (default http://<this Mac LAN IP>:8070)')
    p.add_argument('--clear', action='store_true', help='erase the stored values instead')
    a = p.parse_args(argv)
    if a.clear:
        lines = ['OTA CLEAR', 'OTA?']
    else:
        url = a.url or f'http://{lan_ip()}:8070'
        ssid = input('Owner Wi-Fi SSID: ')
        password = getpass.getpass('Wi-Fi password (empty = open network): ')
        lines = commands(ssid, password, url)
        print('server URL set to the value given/derived (not echoed by the device)')
    for reply in exchange(a.port, lines):
        print(reply)
    return 0


if __name__ == '__main__':
    sys.exit(main())
