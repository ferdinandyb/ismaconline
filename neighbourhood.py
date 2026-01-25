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

last_online_time = None
notified_online = False


def sendemail(msg):
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(mailserver, 465, context=context) as server:
        server.login(user, pwd)
        mail = EmailMessage()
        mail.set_content(body(msg))
        mail["Subject"] = subject(msg)
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


def scan_once(interface_to_scan, mactofind):
    """Perform a single ARP scan and return True if MAC is found."""
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
            if scan_and_print_neighbors(net, interface, mactofind):
                return True
    return False


def handleonline(online, cooldown):
    """Handle state transitions with time-based cooldown."""
    global last_online_time, notified_online
    now = time.time()

    if online:
        if not notified_online:
            sendemail("szippantani kell")
            notified_online = True
        last_online_time = now
        logging.info(f"Device seen, last_online_time updated")
    else:
        if notified_online and last_online_time:
            time_since_last_seen = now - last_online_time
            logging.info(
                f"Device not seen, time since last seen: {time_since_last_seen:.0f}s / {cooldown}s"
            )
            if time_since_last_seen > cooldown:
                sendemail("szippantás történt")
                notified_online = False
                last_online_time = None
                logging.info("Device confirmed offline")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-m", "--mactofind", required=True)
    parser.add_argument(
        "-w",
        "--wait",
        type=int,
        default=60 * 5,
        help="number of seconds to sleep between scans (default: 300 = 5 min)",
    )
    parser.add_argument(
        "-c",
        "--cooldown",
        type=int,
        default=60 * 60 * 2,
        help="number of seconds without seeing device before declaring offline (default: 7200 = 2 hours)",
    )

    args = parser.parse_args()
    logging.info(
        f"Starting with scan interval={args.wait}s, offline cooldown={args.cooldown}s"
    )
    while True:
        online = scan_once(
            interface_to_scan=args.interface.lower(), mactofind=args.mactofind.lower()
        )
        handleonline(online, cooldown=args.cooldown)
        time.sleep(args.wait)
