#! /usr/bin/env python
# vim: set fenc=utf8 ts=4 sw=4 et :
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

from __future__ import absolute_import, division, print_function
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import math
import errno
import os
import sys
import time
from secrets import FROM, mailserver, user, pwd, TO, body, subject
import smtplib
from email.message import EmailMessage

import ssl


logging.basicConfig(
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)

ISONLINE = False


def sendemail(msg):
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(mailserver, 465, context=context) as server:
        server.login(user, pwd)
        mail = EmailMessage()
        mail.set_content(body(msg))
        mail['Subject'] =  subject(msg)
        mail["From"] = FROM
        mail["To"] = TO
        server.send_message(mail)
    print(msg)


def long2net(arg):
    if arg <= 0 or arg >= 0xFFFFFFFF:
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warning("%s is too big. skipping" % net)
        return None

    return net


def scan_and_print_neighbors(net, interface, mactofind, timeout=15):
    logger.info("arping %s on %s" % (net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(
            net, iface=interface, timeout=timeout, verbose=True
        )
        for s, r in ans.res:
            mac = r.sprintf("%Ether.src%")
            if mac == mactofind:
                logger.info("mac found")
                return True
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
            logger.info(line)
    except socket.error as e:
        if e.errno == errno.EPERM:  # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise
    logger.info("mac not found")
    return False


def ismaconline(interface_to_scan=None, mactofind=None, retry_num=5, retry_delay=60):
    if os.geteuid() != 0:
        print("You need to be root to run this script", file=sys.stderr)
        sys.exit(1)

    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:
        if interface_to_scan and interface_to_scan != interface:
            continue

        # skip loopback network and default gw
        if (
            network == 0
            or interface == "lo"
            or address == "127.0.0.1"
            or address == "0.0.0.0"
        ):
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # skip docker interface
        if interface != interface_to_scan and (
            interface.startswith("docker")
            or interface.startswith("br-")
            or interface.startswith("tun")
        ):
            logger.warning("Skipping interface '%s'" % interface)
            continue

        net = to_CIDR_notation(network, netmask)

        if net:
            if net.split(".")[0] != address.split(".")[0]:
                net = ".".join(address.split(".")[:3]) + ".0/24"
            for _ in range(retry_num):
                # it seems the ARP scan can be a bit fickle
                # so try three times before calling quits
                if scan_and_print_neighbors(net, interface, mactofind):
                    return True
                time.sleep(retry_delay)
        return False


def handleonline(online):
    global ISONLINE
    if online == ISONLINE:
        return
    if ISONLINE:
        sendemail("szippantás történt")
        ISONLINE = False
    else:
        # send need szippantás
        sendemail("szippantani kell")
        ISONLINE = True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface")
    parser.add_argument("-m", "--mactofind")
    parser.add_argument("-w", "--wait", default=60*30, help="number of seconds to sleep between checking")
    parser.add_argument("-n","--retry-num", default=5, help="number of retries in a check before accepting negative answer")
    parser.add_argument("-d","--retry-delay", default = 90, help="number of seconds to wait between retries")

    args = parser.parse_args()
    while True:
        online = ismaconline(
            interface_to_scan=args.interface.lower(), mactofind=args.mactofind.lower(), retry_num = args.retry_num, retry_delay=args.retry_delay
        )
        handleonline(online)
        time.sleep(int(args.wait))
