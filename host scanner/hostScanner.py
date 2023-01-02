import socket
import sys
from getmac import get_mac_address as gma 
import struct
import os

def packMac(input_mac):
    #get mac address
    if input_mac.upper() == "MYMAC":
        my_mac = gma()
    else:
        my_mac = input_mac

    #operate on the mac address  
    splited_mac = my_mac.split(":")
    for i in range(len(splited_mac)):
        splited_mac[i] = int(splited_mac[i],16)
    
    #pack the mac address
    packedMac = struct.pack("!6B", *splited_mac)
    return packedMac
    
def eth_addr (a):
  a = list(struct.unpack("!6B",a))
  a = f"{hex(a[0])[2:4]}:{hex(a[1])[2:4]}:{hex(a[2])[2:4]}:{hex(a[3])[2:4]}:{hex(a[4])[2:4]}:{hex(a[5])[2:4]}"
  return a





pid = os.fork()
if pid >0:
    #create a AF_PACKET type raw socket (thats basically packet level)
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error as msg:
        print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print(f"  host ip            host mac address     ")  
    # receive a packet
    while True:
    #1) sniff the ethernet packets that contains my mac address as distination mac address
    #=====================================================================================
        packet = s.recvfrom(65565)
     
        #packet string from tuple
        packet = packet[0]
     
        #parse ethernet header
        eth_length = 14
        #2) extract the host mac address 
        #3)display the host mac address along with his ip
        #4) make sure that there is now repeated macaddresses
        #====================================================
        eth_header = packet[:eth_length]
        eth = struct.unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        discovered = [] 
        if packet[0:6] == packMac("mymac"):
            if packet[0:6] not in discovered:
                discovered.append(packet[0:6])	
                src_ip = packet[28: 32]
                src_ip = socket.inet_ntoa(src_ip)
                print(f"{src_ip}      {eth_addr(packet[6:12])}")
else:
    #1) open socket for sending arp requests
    #=======================================
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    rawSocket.bind(("eth0", socket.htons(0x0800)))
    #2)start counting from ip = 192.168.1.0 to ip = 192.168.1.254
    #=============================================================
    for i in range(1,255,1):
        ip = f"192.168.1.{i}"
        #3) at each eduration send arp packet to that ip
        #===============================================
        packed_source_mac =  packMac("mymac")      # sender mac address
        packed_local_mac =   packMac("ff:ff:ff:ff:ff:ff") # target mac address
        source_ip  = "192.168.1.12"            # sender ip address  
        dest_ip  = ip               # target ip address

        # Ethernet Header
        protocol = 0x0806                       # 0x0806 for ARP
        packed_proto = struct.pack("!H", protocol)
        eth_hdr = packed_local_mac + packed_source_mac + packed_proto
        

        # ARP header
        htype = 1                               # Hardware_type ethernet
        ptype = 0x0800                          # Protocol type TCP
        hlen = 6                                # Hardware address Len
        plen = 4                                # Protocol addr. len
        operation = 1                           # 1=request/2=reply
        dest_mac = packMac("ff:ff:ff:ff:ff:ff")  # target mac address
        src_ip = socket.inet_aton(source_ip)
        dst_ip = socket.inet_aton(dest_ip)

        arp_hdr = struct.pack("!HHBBH",htype,ptype,hlen,plen,operation) + packed_source_mac + struct.pack("!4s", src_ip)  + packed_local_mac + struct.pack("!4s", dst_ip)

        packet = eth_hdr + arp_hdr 

        rawSocket.send(packet)
    rawSocket.close()
    

    

  
  