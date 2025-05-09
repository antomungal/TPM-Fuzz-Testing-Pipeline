
import struct
import random

class TPMException(Exception):
    pass

class BufferOverflow(TPMException):
    pass

class MalformedCommand(TPMException):
    pass

class TPMHandler:
    def __init__(self, buffer_size=4096):
        self.buffer = bytearray(buffer_size)
        self.max_size = buffer_size
        self.session_nonce = self.generate_nonce()

    def generate_nonce(self):
        return random.randbytes(16)

    def clear_buffer(self):
        for i in range(len(self.buffer)):
            self.buffer[i] = 0

    def load_command(self, data: bytes):
        if len(data) > self.max_size:
            raise BufferOverflow("Input exceeds TPM buffer limit.")
        self.clear_buffer()
        self.buffer[:len(data)] = data

    def parse_header(self):
        if len(self.buffer) < 10:
            raise MalformedCommand("TPM command too short.")
        tag, size, command_code = struct.unpack(">H I H", self.buffer[:8])
        if size > self.max_size:
            raise BufferOverflow("Declared size exceeds maximum buffer size.")
        return tag, size, command_code

    def parse_session(self):
        session_offset = 8
        nonce_len = self.buffer[session_offset]
        if session_offset + 1 + nonce_len > self.max_size:
            raise BufferOverflow("Nonce read exceeds buffer limits.")
        nonce = self.buffer[session_offset + 1: session_offset + 1 + nonce_len]
        return nonce

    def handle(self):
        try:
            tag, size, command_code = self.parse_header()
            nonce = self.parse_session()
            print(f"Parsed command: tag=0x{tag:X}, size={size}, code=0x{command_code:X}, nonce={nonce.hex()}")
            return True
        except TPMException as e:
            print(f"TPM Error: {str(e)}")
            return False
