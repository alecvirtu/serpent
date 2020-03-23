import socket
import time
import asyncio
from hashlib import sha256
from io import BytesIO
from random import randint
from loguru import logger

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'
BTC_PORT = 8333

def hash256(s):
    return sha256(sha256(s).digest()).digest()

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i < 0x100000000:
        return b'\xfe' + i.to_bytes(4, 'little')
    elif i < 0x10000000000000000:
        return b'\xff' + i.to_bytes(8, 'little')
    else:
        raise ValueError('integer too large: {}'.format(i))

def decode_varint(s):
    i = s.read(1)[0]
    if i == 0xfd:
        return int.from_bytes(s.read(2), 'little')
    elif i == 0xfe:
        return int.from_bytes(s.read(4), 'little')
    elif i == 0xff:
        return int.from_bytes(s.read(8), 'little')
    else:
        return i

class Address:

    def __init__(self, ip, port, timestamp=False):
        self.ip = ip
        self.port = port
        self.timestamp = timestamp

    def __repr__(self):
        # surround ipv6 addresses with square brackets to distinguish between
        # address and port as per RFC 3986
        ip = f'[{self.ip}]' if ':' in self.ip else self.ip
        return '{}:{}'.format(ip, self.port)

    def __eq__(self, other):
        # addresses are identical even if they different timestamps
        return self.ip == other.ip and self.port == other.port

    def __hash__(self):
        # addresses are identical even if they different timestamps
        return hash((self.ip, self.port))


class NetworkEnvelope:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload
        self.magic = NETWORK_MAGIC

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    async def parse(cls, s, timeout):
        # check the network magic
        magic = await s.readexactly(4)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('Wrong magic: {}'.format(magic.hex()))

        # command 12 bytes
        command = await s.readexactly(12)

        # strip the trailing 0's
        command = command.rstrip(b'\x00')

        # payload length 4 bytes, little endian
        payload_length = int.from_bytes(await s.readexactly(4), 'little')

        # checksum 4 bytes, first four of hash256 of payload
        checksum = await s.readexactly(4)

        # payload is of length payload_length
        payload = await s.readexactly(payload_length)
        logger.trace(f'decoded message - advertised payload length: {payload_length} length of read() payload: {len(payload)}')


        # verify checksum
        candidate_checksum = hash256(payload)[:4]
        logger.trace(f'decoded message - command: {command} payload: {payload.hex()} checksum: {checksum.hex()} local checksum: {candidate_checksum.hex()}')
        if candidate_checksum != checksum:
            raise RuntimeError('Derived checksum {} does not match specified checksum {}'.format(candidate_checksum, checksum))

        # return an instance of the class
        return cls(command, payload)

    def serialize(self):
        result = self.magic
        # padded with zeros for a length of twelve bytes
        result += self.command + b'\00' * (12 - len(self.command))
        result += len(self.payload).to_bytes(4, 'little')
        result += hash256(self.payload)[:4]
        result += self.payload
        return result

    def stream(self):
        return BytesIO(self.payload)


class VersionMessage:
    command = b'version'

    def __init__(self, version=70015, services=0, timestamp=None,
                 receiver_services=0,
                 receiver_ip=b'\x00\x00\x00\x00', receiver_port=BTC_PORT,
                 sender_services=0,
                 sender_ip=b'\x00\x00\x00\x00', sender_port=BTC_PORT,
                 nonce=None, user_agent=b'/serpent:0.1.1/',
                 latest_block=0, relay=False):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = randint(0, 2**64).to_bytes(8, 'little')
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    @classmethod
    def parse(cls, s):
        version = int.from_bytes(s.read(4), 'little')
        services = int.from_bytes(s.read(8), 'little')
        timestamp = int.from_bytes(s.read(8), 'little')
        receiver_services = int.from_bytes(s.read(8), 'little')
        receiver_ip = s.read(16)[12:]
        receiver_port = int.from_bytes(s.read(2), 'big')
        sender_services = int.from_bytes(s.read(8), 'little')
        sender_ip = s.read(16)[12:]
        sender_port = int.from_bytes(s.read(2), 'big')
        nonce = s.read(8)
        user_agent_length = decode_varint(s)
        user_agent = s.read(user_agent_length)
        latest_block = int.from_bytes(s.read(4), 'little')
        relay = s.read(1)
        return cls(version, services, timestamp, receiver_services, receiver_ip, receiver_port, sender_services, sender_ip, sender_port, nonce, user_agent, latest_block, relay)

    def serialize(self):
        # version is 4 bytes little endian
        result = self.version.to_bytes(4, 'little')

        # services is 8 bytes little endian
        result += self.services.to_bytes(8, 'little')

        # timestamp is 8 bytes little endian
        result += self.timestamp.to_bytes(8, 'little')

        # receiver services is 8 bytes little endian
        result += self.receiver_services.to_bytes(8, 'little')

        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        result += b'\x00' * 10 + b'\xff' * 2 + self.receiver_ip

        # receiver port is 2 bytes, big endian
        result += self.receiver_port.to_bytes(2, 'big')

        # sender services is 8 bytes little endian
        result += self.sender_services.to_bytes(8, 'little')

        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        result += b'\x00' * 10 + b'\xff' * 2 + self.sender_ip

        # sender port is 2 bytes, big endian
        result += self.sender_port.to_bytes(2, 'big')

        # nonce should be 8 bytes
        result += self.nonce

        # useragent is a variable string, so varint first
        result += encode_varint(len(self.user_agent))
        result += self.user_agent

        # latest block is 4 bytes little endian
        result += self.latest_block.to_bytes(4, 'little')

        # relay is 00 if false, 01 if true
        if self.relay:
            result += b'\x01'
        else:
            result += b'\x00'

        return result

class GetAddrMessage:
    command = b'getaddr'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


class VerAckMessage:
    command = b'verack'

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b''


class PingMessage:
    command = b'ping'

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b'pong'

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class AddrMessage:
    command = b'addr'

    def __init__(self, addresses):
        self.addresses = addresses

    @classmethod
    def parse(cls, stream):
        num_addresses = decode_varint(stream)
        addresses = []
        for _ in range(num_addresses):
            timestamp = int.from_bytes(stream.read(4), 'little') # timestamp
            _ = stream.read(8)      # services
            ip = stream.read(16)    # ip address
            if ip[:12] == b'\x00' * 10 + b'\xff' * 2:
                ip = socket.inet_ntop(socket.AF_INET, ip[12:])
            else:
                ip = socket.inet_ntop(socket.AF_INET6, ip)
            port = int.from_bytes(stream.read(2), 'big') # port
            addresses.append(Address(ip, port, timestamp=timestamp))
        return cls(addresses)

class MinimalNode:
    def __init__(self, address):
        self.address = address

    async def establish(self, timeout=None):
        fut = asyncio.open_connection(self.address.ip, self.address.port)
        self.reader, self.writer = await asyncio.wait_for(fut, timeout=timeout)

    def terminate(self):
        self.socket.shutdown(SHUT_RDWR)
        self.socket.close()

    async def get_peers(self):
        message = GetAddrMessage()
        self.send(message)

        # Receive multiple 'addr' replies for up to thirty seconds.
        # Stop waiting when no 'addr' message received for ten seconds.
        start = int(time.time())
        peers = set()
        while time.time() - start < 30:
            try:
                message = await self.wait_for(AddrMessage, timeout=10)
            except asyncio.TimeoutError:
                break
            peers |= set(message.addresses)

        return peers

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()

    async def handshake(self, user_agents):
        version = VersionMessage()
        self.send(version)
        message = await self.wait_for(VersionMessage, timeout=10)
        logger.trace(f'handshake successful with [{self.address}]')
        # record user agent
        if not message.user_agent in user_agents:
            user_agents[message.user_agent] = 0
        user_agents[message.user_agent] += 1

    def send(self, message):
        envelope = NetworkEnvelope(message.command, message.serialize())
        self.writer.write(envelope.serialize())

    async def read(self, timeout=False):
        envelope = await NetworkEnvelope.parse(self.reader, timeout=timeout)
        return envelope

    async def wait_for(self, *message_classes, timeout=None):
        command = None
        command_to_class = {m.command: m for m in message_classes}
        start = time.time()
        while command not in command_to_class.keys():
            envelope = await asyncio.wait_for(self.read(), timeout=timeout)
            logger.trace(f'received from [{self.address}]: {envelope}')
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
                logger.trace(f'sent to host [{self.address}]: VERACK')
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
                logger.trace(f'sent to host [{self.address}]: PONG')
        return command_to_class[command].parse(envelope.stream())
