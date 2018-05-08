#!/usr/bin/python 
"""
   Author : Amit K Nepal
   Email: amit@amitnepal.com
   
   Python Script to get the Samba ipVersion since the enum4linux stopped working.
   This script sends a smbclient -L command, sniffs the packets and gets the samba ipVersion.
   The sniffing part is based on : https://www.binarytides.com/python-packet-sniffer-code-linux/
   
   Disclaimer: This tool is provided as is with no warranty what so ever. This tools is for educational purposees only and You are solely responsible for the usage of this script. 

"""
import subprocess
import socket, sys
from struct import *
import unicodedata
import string
import re
import argparse

debug = False
trace = False
verbose = False
searchString = "UnixSamba"

def printableCharacters(str):
    """ Removes non printable characters. Requires string module."""
    printable = set(string.printable)
    return filter(lambda x: x in printable, str)

def debug_print(msg):
    """ Print only if debug mode is set """
    if debug:
        print msg
        
def get_macAddress (macInfo) :
    """ ord => Given a string of length one, return an integer representing the Unicode code point of the character when the argument is a unicode object, or the value of the byte when the argument is an 8-bit string."""
    macAddress = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(macInfo[0]) , ord(macInfo[1]) , ord(macInfo[2]), ord(macInfo[3]), ord(macInfo[4]) , ord(macInfo[5]))
  
    return macAddress
  
def process_packets(packet, server):
        
        packet = packet[0] #packet string from tuple
        ethernetLength = 14#parse ethernet header
        ethernetHeader = packet[:ethernetLength]
        eth = unpack('!6s6sH' , ethernetHeader)
        eth_protocol = socket.ntohs(eth[2])
        debug_print("Destination MAC:{0} , Source MAC: {1} , Protocol: {2}".format(get_macAddress(packet[0:6]), get_macAddress(packet[6:12]), str(eth_protocol) ))
       
        if eth_protocol == 8 : #Parse IP packets, IP Protocol number = 8
            #Parse IP header take first 20 characters for the ip header
            ipHeaders = packet[ethernetLength:20+ethernetLength]
            ipHeader = unpack('!BBHHHBBH4s4s' , ipHeaders) #unpack the ip headers
     
            ipHeaderLengthVersion = ipHeader[0]
            ipVersion = ipHeaderLengthVersion >> 4 #shift headerlength right by 4 bits
            ipHeaderLength = ipHeaderLengthVersion & 0xF
     
            ipheader_Length = ipHeaderLength * 4
     
            ttl = ipHeader[5]
            protocol = ipHeader[6]
            s_addr = socket.inet_ntoa(ipHeader[8]);
            d_addr = socket.inet_ntoa(ipHeader[9]);
            
            if s_addr != server:
                return ""
            
            debug_print("IP Version:{0}, IP Header Length:{1}, TTL {2}, Protocol:{3}, Source Address:{4}, Destination Address:{5}".format(str(ipVersion), str(ipHeaderLength), str(ttl), str(protocol), str(s_addr), str(d_addr)))
     
            #TCP protocol
            if protocol == 6 :
                totalHeaderLength = ipheader_Length + ethernetLength
                tcp_header_raw = packet[totalHeaderLength:totalHeaderLength+20]
     
                #now unpack them :)
                tcpHeader = unpack('!HHLLBBHHH' , tcp_header_raw)
                 
                source_port = tcpHeader[0]
                dest_port = tcpHeader[1]
                sequence = tcpHeader[2]
                acknowledgement = tcpHeader[3]
                doff_reserved = tcpHeader[4]
                tcpHeaderLength = doff_reserved >> 4
                
                debug_print("Source Port:{0}, Dest Port: {1}, SEQ : {2}, ACK:{3}, TCP header Length:{4}".format(str(source_port), str(dest_port), str(sequence), str(acknowledgement), str(tcpHeaderLength)))    
                
                headerSize = ethernetLength + ipheader_Length + tcpHeaderLength * 4
                data_size = len(packet) - headerSize
                
                dataInPacket = packet[headerSize:]#get dataInPacket from the packet
                try:
                    dataInPacket = unicodedata.normalize('NFKD', dataInPacket).encode('ascii','ignore')
                except:
                    dataInPacket = printableCharacters(dataInPacket)  
                if searchString in dataInPacket:
                        print re.findall(r"(?<={0}\s)\S+".format(searchString),dataInPacket)[0]
                if verbose:
                    print dataInPacket

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="Display Verbose Message", action="store_true")
parser.add_argument("-d", "--debug", help="Debug Mode On", action="store_true")
parser.add_argument("-s", "--server", help="Samba Server Hostname or IP Address")
parser.add_argument("-totalHeaderLength", "--trace", help="Display Everything", action="store_true")                 
args = parser.parse_args()

if not args.server:
    print "Please Specify Samba Server with -s or --server option"                        
    sys.exit(1)                 

if args.debug:
    debug = True
if args.trace:
    trace = True
if args.verbose:
	verbose = True
    
server = args.server    
p = subprocess.Popen(['smbclient', '-NL',server], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 

while p.poll() is None:
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        packet = s.recvfrom(65565)
        process_packets(packet, server)
    except socket.error , msg:
        print("Unable to create socket. Error Code:{0}, Message:{1}".format(str(msg[0]), str(msg[1])))
        sys.exit(1)                      
