import hashlib
from scapy.all import *

PORT = 99
ASCII_SHIFT = 97  # ascii value of 'a'
NUM_LETTERS = 26  # letters in ABC
location = []
HEADER = "FLY008"
srcport = 0
SERVERIP = "54.71.128.194"
SEND_STRING = "location_md5=%%MD5%%,airport=nevada25.84,time=15:52,lane=earth.jup,vehicle=2554,fly"
REPLACE = "%%MD5%%"
ENCRYPT_KEY = 8


def decrypt(buff, key):
    """
    This function decrypts a message according to the key. This shifts every EVEN (zugi) letter using shift_letter function
    param buff: buffer to decrypt
    type buff: str
    param key: number to shift
    type key: int
    return: decrypted message
    rtype: str
    """
    new_buff = ""
    for index in range(len(buff)):
        if index % 2 == 0:  # if it's an even number index (ZUGI)
            new_buff += shift_letter(buff[index], key)  # add letter after shifting it
        else:
            new_buff += buff[index]  # add letter as is
    return new_buff


def shift_letter(letter, key):
    """
    This function decrypts shifts a single letter KEY times BACK in the abc, aslong as it's alphabet
    param letter: letter to shift
    type letter: str
    param key: number to shift
    type key: int
    return: shifted letter
    rtype: str
    """
    if not letter.isalpha():
        return letter
    index = ord(letter)-ASCII_SHIFT
    new_index = (index-key) % 26
    return chr(ASCII_SHIFT+new_index)


def encrypt(buff, key):
    return decrypt(buff, key*-1)


def read_msg(msg):
    """
    this reads the message (header and body, decrypts the body and returns key+body
    param msg: full raw msg from server
    type msg: str
    return: the message key and decrypted message
    rtype: tuple
    """
    try:
        code = msg[0:3]
        cypher_key = int(msg[3:6])
        text = msg[6:]
        new_text = decrypt(text, cypher_key)
        return cypher_key, new_text
    except Exception as exception:
        print("Error:", exception)
        return ""


def filter_et(packet):
    """
    Filter function to get all incoming outgoing UDP port 99
    param packet: text
    type packet: scapy packet
    return: True if packet is udp port PORT
    rtype: bool
    """
    return IP in packet and UDP in packet and (packet[UDP].sport == PORT or packet[UDP].dport == PORT)


def printer(packet):
    """
    Filter function to get all incoming outgoing UDP port 99
    param packet: text
    type packet: scapy packet
    return: True if packet is udp port PORT
    rtype: bool
    """
    global srcport
    if (packet[UDP].sport != PORT):
        srcport = packet[UDP].sport
    rawtext = packet[Raw].load.decode()
    cypher_key, new_text = read_msg(rawtext)
    print("#KEY=", cypher_key, "\t", new_text)
    if "/10" in new_text:
        location.append(new_text[-10:])
        if "10/10" in new_text:
            sendfly("".join(location))


def sendfly(location):
    """
    sends the FLY messge using location given, global srcport and const PORT and SERVERIP
    the message is taken from SEND_STRING, added with md5 of location, then encrypted with ENCRYPT_KEY (could be anything)
    param location: 100 chars location collected
    type location: str
    return: none
    """
    print("full location is:", location)
    buff = SEND_STRING.replace(REPLACE, hashlib.md5(location.encode()).hexdigest())
    buff = HEADER + encrypt(buff, ENCRYPT_KEY)
    print(buff)
    full_msg = Ether() / IP(dst=SERVERIP) / UDP(sport=srcport, dport=PORT) / buff
    print(full_msg.show())
    sendp(full_msg)


def main():
    sniff(lfilter=filter_et, prn=printer)


if __name__ == '__main__':
    main()
