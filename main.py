import argparse
import ipaddress
import math
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat


DNS_QUERY = bytes.fromhex('1234010000010000000000000000020001')
ECHO_QUERY = b'portscan echo\r\n'
HTTP_QUERY = b'HEAD / HTTP/1.0\r\n\r\n'


def parse_ports(specs):
    ports = {'tcp': set(), 'udp': set()}
    for spec in specs or ['tcp', 'udp']:
        protocol, _, ranges = spec.partition('/')
        if protocol not in ports:
            raise ValueError(f'неизвестный протокол: {protocol}')
        for item in (ranges or '1-65535').split(','):
            first, separator, last = item.partition('-')
            start = int(first)
            end = int(last) if separator else start
            if not 1 <= start <= end <= 65535:
                raise ValueError(f'неверный диапазон портов: {item}')
            ports[protocol].update(range(start, end + 1))
    return [(protocol, port) for protocol in ports for port in sorted(ports[protocol])]


def is_dns_response(data):
    return len(data) >= 12 and data[:2] == DNS_QUERY[:2] and bool(data[2] & 0x80)


def guess_tcp(family, address, timeout):
    dns_request = len(DNS_QUERY).to_bytes(2, 'big') + DNS_QUERY
    for protocol, request in [('HTTP', HTTP_QUERY), ('DNS', dns_request), ('ECHO', ECHO_QUERY)]:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(address)
                sock.sendall(request)
                with sock.makefile('rb') as response:
                    if protocol == 'HTTP' and response.read(5) == b'HTTP/':
                        return protocol
                    if protocol == 'DNS':
                        length = int.from_bytes(response.read(2), 'big')
                        if length >= 12 and is_dns_response(response.read(12)):
                            return protocol
                    if protocol == 'ECHO' and response.read(len(request)) == request:
                        return protocol
        except OSError:
            continue
    return '-'


def scan_port(target, ip, timeout, verbose, guess):
    protocol, port = target
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    address = (str(ip), port)
    result = f'{protocol.upper()} {port}'
    detected = '-'
    try:
        if protocol == 'tcp':
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                start = time.perf_counter()
                sock.connect(address)
                elapsed = (time.perf_counter() - start) * 1000
            if verbose:
                result += f' {elapsed:.2f}'
            if guess:
                detected = guess_tcp(family, address, timeout)
        else:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect(address)
                sock.send(DNS_QUERY)
                sock.send(ECHO_QUERY)
                deadline = time.monotonic() + timeout
                received = False
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        data = sock.recv(65535)
                    except OSError:
                        break
                    received = True
                    if not guess:
                        break
                    if is_dns_response(data):
                        detected = 'DNS'
                        break
                    if data == ECHO_QUERY:
                        detected = 'ECHO'
                        break
                if not received:
                    return None
    except OSError:
        return None
    if guess:
        result += f' {detected}'
    return result


def main():
    parser = argparse.ArgumentParser(prog='portscan')
    parser.add_argument('--timeout', type=float, default=2)
    parser.add_argument('-j', '--num-threads', type=int, default=32)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-g', '--guess', action='store_true')
    parser.add_argument('ip_address', type=ipaddress.ip_address)
    parser.add_argument('ports', nargs='*', metavar='PORTS')
    args = parser.parse_intermixed_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout должен быть положительным конечным числом')
    if args.num_threads < 1:
        parser.error('--num-threads должен быть больше нуля')
    try:
        targets = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    with ThreadPoolExecutor(max_workers=args.num_threads) as pool:
        results = pool.map(scan_port, targets, repeat(args.ip_address), repeat(args.timeout),
                           repeat(args.verbose), repeat(args.guess))
        for result in results:
            if result is not None:
                print(result)


if __name__ == '__main__':
    main()
