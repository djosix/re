#!/usr/bin/env python3
"""Bridge a local serial device to a TCP port on 127.0.0.1 (stdlib only).

Runs on the host so the sandbox never gets device access. The relay forwards
relay:PORT -> host.docker.internal:PORT, and inside the sandbox
`serial-attach PORT` turns it into a pty. One client at a time; a new client
replaces the old one. Baud rate and framing are fixed here (8N1, no flow control).

    python3 -I host/serial-bridge.py /dev/cu.usbserial-XXXX --baud 115200 --port 7000
"""
import argparse
import errno
import fcntl
import os
import select
import signal
import socket
import struct
import sys
import termios
import time

IOSSIOSPEED = 0x80045402  # macOS: arbitrary baud rates


def open_serial(path, baud):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
    iflag = 0
    oflag = 0
    lflag = 0
    cflag &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB)
    cflag |= termios.CS8 | termios.CLOCAL | termios.CREAD
    if hasattr(termios, "CRTSCTS"):
        cflag &= ~termios.CRTSCTS
    cc[termios.VMIN] = 0
    cc[termios.VTIME] = 0
    const = getattr(termios, "B%d" % baud, None)
    if const is not None:
        ispeed = ospeed = const
    termios.tcsetattr(fd, termios.TCSANOW, [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])
    if const is None:
        if sys.platform != "darwin":
            raise SystemExit("baud %d not supported by termios on this platform" % baud)
        fcntl.ioctl(fd, IOSSIOSPEED, struct.pack("L", baud))
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def log(msg):
    sys.stderr.write(time.strftime("%Y/%m/%d %H:%M:%S ") + msg + "\n")
    sys.stderr.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("device")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--port", type=int, default=7000)
    ap.add_argument("--bind", default="127.0.0.1", help="keep loopback unless you know why not")
    args = ap.parse_args()

    fd = open_serial(args.device, args.baud)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(1)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log("serial %s @%d 8N1  <->  tcp %s:%d" % (args.device, args.baud, args.bind, args.port))

    client = None
    pending = b""  # serial -> client bytes not yet written
    try:
        while True:
            rlist = [srv, fd] + ([client] if client else [])
            wlist = [client] if (client and pending) else []
            r, w, _ = select.select(rlist, wlist, [], 1.0)
            if srv in r:
                new, addr = srv.accept()
                if client:
                    log("replacing client")
                    client.close()
                client, pending = new, b""
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                log("client connected from %s:%d" % addr)
                continue
            if fd in r:
                try:
                    data = os.read(fd, 4096)
                except OSError as e:
                    if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        data = b""
                    else:
                        raise SystemExit("serial read failed: %s" % e)
                if data and client:
                    pending = (pending + data)[-(1 << 20):]  # drop oldest beyond 1 MiB
            if client and client in w and pending:
                try:
                    n = client.send(pending)
                    pending = pending[n:]
                except OSError:
                    log("client gone")
                    client.close()
                    client, pending = None, b""
            if client and client in r:
                try:
                    data = client.recv(4096)
                except OSError:
                    data = b""
                if not data:
                    log("client disconnected")
                    client.close()
                    client, pending = None, b""
                else:
                    view = memoryview(data)
                    while view:
                        try:
                            n = os.write(fd, view)
                            view = view[n:]
                        except OSError as e:
                            if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                                raise SystemExit("serial write failed: %s" % e)
                            select.select([], [fd], [], 1.0)
    except KeyboardInterrupt:
        pass
    finally:
        if client:
            client.close()
        srv.close()
        os.close(fd)


if __name__ == "__main__":
    main()
