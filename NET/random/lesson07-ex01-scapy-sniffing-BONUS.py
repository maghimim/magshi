import json
import requests
from scapy.all import *

COUNTRY = "France"
GEO = "http://ip-api.com/json/"
KEY = "country"
PORT = 443


def get_country(ipaddr):
	'''
	this function get an IP address and find, 
	with the help of requests and ip-api.com wedsite,
	what's the country of it.
	:param ipaddr: the IP address.
	:type ipaddr: string
	:return: IP address's country.
	:rtype: string
	'''
    geo_addr = GEO + ipaddr
    ans = requests.get(geo_addr)
    text = ans.text
    ansdict = json.loads(text)
    country = "None"
    if KEY in ansdict:
        country = ansdict[KEY]
    print(country)
    return country


def geofilter(pkt):
	"""
	filter function.
	return if the packet is from a HTTP server.
	:param pkt: sniffed packet
	:type pkt: scapy packet
	:return: if the packet is from a HTTP server.
	:rtype: Bool.
	"""
    return TCP in pkt and pkt[TCP].sport == PORT


def printpacket(pkt):
	"""
	this function get a packet and print what's the country of the src IP.
	:param pkt: sniffed packet
	:type pkt: scapy packet
	:return: the country.
	:rtype: string
	"""
    print(get_country(str(pkt[IP].src)))


def main():
    sniff(lfilter=geofilter, prn=printpacket)


if __name__ == '__main__':
    main()
