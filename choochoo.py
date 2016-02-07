import logging
import re
import socket
import time

import config

logging.basicConfig(level=logging.DEBUG)
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
        self.headers = None
        self.body = None

    def add_command(self, command):
        self.command = command

    def add_header(self, name, value):
        # Only the first instance of a given header is considered.  (see spec)
        if name not in headers:
            self.headers[name] = value

    def add_body(self, body):
        self.body = body


def read_frame(frame_receiver):
    while True:
        frame = Frame()

        # ------------
        # Read Command
        # ------------
        logger.debug('reading command')
        command = bytearray()

        while True:
            octal = (yield)
            logger.debug('read: {}'.format(octal))

            if octal is not LINE_FEED:
                command.append(octal)

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
                if octal is COLON:
                    break
                name.append(value)
                octal = (yield)

            # Read the header value
            while True:
                if octal is LINE_FEED:
                    break
                value.append(octal)
                octal = (yield)

            frame.add_header(name, value)

        # ---------
        # Read Body
        # ---------
        logger.debug('reading body')
        body = bytearray()

        while True:
            octal = (yield)
            if octal is not NULL:
                body.append(octal)

        frame.add_body(body)

        # ----
        # Done
        # ----
        frame_reciever.send(frame)

        # TODO: Clear following line feeds


class ProtocolError(Exception):
    pass


def frame_reciever():
    while True:
        frame = (yield)
        logger.debug(frame)


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

    # reciever = frame_reciever()
    # reciever.send(None)

    # unwrapper = read_frame(reciever)
    #unwrapper.send(None)

    # for byte in sock.recv(BUFFER_SIZE):
    #     unwrapper.send(byte)

    logger.debug(sock.recv(BUFFER_SIZE))

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


if __name__ == '__main__':
    main()
