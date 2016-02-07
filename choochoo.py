import sys
import logging
import re
import socket
import time
import zlib

import config

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


BUFFER_SIZE = 4096
ENCODING = 'utf-8'
LINE_FEED = 10
COLON = 58
NULL = 0


def create_frame(command, headers={}, body=None):
    if body is not None and command is not 'SEND':
        raise ProtocolError('Only SEND may have a body')

    # Add the command
    frame = bytearray(command, ENCODING)
    frame.append(LINE_FEED)

    # Add the headers
    # TODO: Encode header escape sequences 13, 10, 58, 92
    for k, v in headers.items():
        frame.extend(k.encode(ENCODING))
        frame.append(COLON)
        frame.extend(v.encode(ENCODING))
        frame.append(LINE_FEED)
    frame.append(LINE_FEED)

    # Add the body
    if body is not None:
        if isinstance(body, str):
            frame.extend(body.encode(ENCODING))
        elif isinstance(body, bytearray) or isinstance(body, bytes):
            frame.extend(body)
        else:
            raise TypeError('body must be a str, bytearray, or bytes')

    frame.append(NULL)
    return frame


class Frame():
    def __init__(self):
        self.command = None
        self.headers = {}
        self.body = None

    def add_command(self, command):
        self.command = command.decode(ENCODING)

    def add_header(self, name, value):
        n = name.decode(ENCODING)
        v = value.decode(ENCODING)

        # Only the first instance of a given header is considered.  (see spec)
        if n not in self.headers:
            self.headers[n] = v

    def add_body(self, body):
        self.body = body

    def __repr__(self):
        return '<Frame {} {}>'.format(self.command, self.headers)


def read_frame(frame_processor=None):
    while True:
        frame = Frame()

        # ------------
        # Read Command
        # ------------
        logger.debug('reading command')
        command = bytearray()

        while True:
            octal = (yield)

            if octal is LINE_FEED:
                # Clear any leading line feeds (messy)
                if not command:
                    continue
                break

            command.append(octal)

        logger.debug('read command: {}'.format(command))
        frame.add_command(command)

        # ------------
        # Read Headers
        # ------------
        logger.debug('reading headers')
        name = bytearray()
        value = bytearray()

        while True:
            octal = (yield)

            if octal is LINE_FEED:
                break

            # Read the header name
            while True:
                name.append(octal)
                octal = (yield)
                if octal is COLON:
                    octal = (yield)
                    break

            # Read the header value
            while True:
                if octal is LINE_FEED:
                    break
                value.append(octal)
                octal = (yield)

            logger.debug('read header: {}:{}'.format(name, value))
            frame.add_header(name, value)

            name = bytearray()
            value = bytearray()

        # ---------
        # Read Body
        # ---------
        logger.debug('reading body')
        body = bytearray()
        body_read = False

        # Read specific length
        if 'content-length' in frame.headers.keys():
            bytes_remaining = int(frame.headers['content-length'])

            while bytes_remaining:
                octal = (yield)
                bytes_remaining -= 1
                body.append(octal)

            body_read = True

        # Read till NULL
        while True:
            octal = (yield)

            if octal is NULL:
                break

            # Discard data if we've already read body as per content-length
            if body_read:
                continue

            body.append(octal)

        logger.debug('read body: {}'.format(body))
        frame.add_body(body)

        # ----
        # Done
        # ----
        if frame_processor:
            frame_processor(frame)


class ProtocolError(Exception):
    pass


def main():
    host, port = re.match('.*://(.+):(\d+)', config.STOMP_BROKER_URI).groups()

    sock = socket.create_connection((host, port))
    logger.debug(sock)

    connect_frame = create_frame(
        'CONNECT',
        {
            'accept-version': '1.2',
            'host': host,
            'login': config.STOMP_USERNAME,
            'passcode': config.STOMP_PASSWORD,
        }
    )
    sock.sendall(connect_frame)

    def process_frame(frame):
        logger.info(frame)
        if frame.command == 'MESSAGE':
            sys.stdout.buffer.write(frame.body)

    unwrapper = read_frame(frame_processor=process_frame)
    unwrapper.send(None)

    for byte in sock.recv(BUFFER_SIZE):
        unwrapper.send(byte)

    subscribe_frame = create_frame(
        'SUBSCRIBE',
        {
            'id': '0',
            'destination': config.STOMP_QUEUE,
            'ack': 'auto',
        }
    )
    sock.sendall(subscribe_frame)

    # for byte in sock.recv(BUFFER_SIZE):
    #     unwrapper.send(byte)

    # run_till = time.time() + 10
    # while time.time() < run_till:
    while True:
        buff = sock.recv(BUFFER_SIZE)
        for byte in buff:
            unwrapper.send(byte)

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


if __name__ == '__main__':
    main()
