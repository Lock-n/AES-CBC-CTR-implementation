import math

from Crypto.Cipher import AES


def xorb(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])


# def sum_bytes(bytes1, bytes2):
#    return bytes([b1 + b2 for b1, b2 in zip(bytes1, bytes2)])


def cbc_encrypt(message: bytes, key: bytes, IV: bytes) -> bytes:
    BLOCK_SIZE = 16
    BLOCKS_NUMBER = math.ceil(len(message) / BLOCK_SIZE)

    aes = AES.new(key)
    message_blocks = []

    for i in range(BLOCKS_NUMBER):
        if i == BLOCKS_NUMBER -1:
            remainder_bytes_length = BLOCK_SIZE - (len(message) % BLOCK_SIZE)

            if remainder_bytes_length == 0:
                remainder_bytes_length = BLOCK_SIZE

            remainder_bytes = bytearray()

            for i2 in range(remainder_bytes_length):
                remainder_bytes.append(remainder_bytes_length)

            message_blocks.append(message[i * BLOCK_SIZE:] + remainder_bytes)
        else:
            message_blocks.append(message[i * BLOCK_SIZE:(i +1) * BLOCK_SIZE])

    cipher_blocks = []

    cipher_blocks.append(aes.encrypt(xorb(IV, message_blocks[0])))

    for i in range(1, BLOCKS_NUMBER):
        cipher_blocks.append(aes.encrypt(xorb(cipher_blocks[i -1], message_blocks[i])))

    cipher = bytes()

    for block in cipher_blocks:
        cipher += block

    return IV + cipher


def cbc_decrypt(cipher: bytes, key: bytes) -> bytes:
    BLOCK_SIZE = 16
    BLOCKS_NUMBER = int(len(cipher) / BLOCK_SIZE) - 1

    aes = AES.new(key)
    IV = cipher[:BLOCK_SIZE]

    cipher_blocks = []

    for i in range(BLOCKS_NUMBER):
        cipher_blocks.append(cipher[(i + 1) * BLOCK_SIZE:(i + 2) * BLOCK_SIZE])

    message_blocks = []

    message_blocks.append(xorb(aes.decrypt(cipher_blocks[0]), IV))

    for i in range(1, BLOCKS_NUMBER):
        message_blocks.append(xorb(aes.decrypt(cipher_blocks[i]), cipher_blocks[i - 1]))

    #  Remove pad
    pad_length = message_blocks[BLOCKS_NUMBER-1][BLOCK_SIZE-1]

    if pad_length == 16:
        message_blocks.pop(BLOCKS_NUMBER-1)
    else:
        message_blocks[BLOCKS_NUMBER-1] = message_blocks[BLOCKS_NUMBER-1][:BLOCK_SIZE -pad_length]

    message = bytes()
    for block in message_blocks:
        message += block

    return message


def ctr_encrypt(message: bytes, key: bytes, IV: bytes) -> bytes:



    BLOCK_SIZE = 16
    BLOCKS_NUMBER = math.ceil(len(message) / BLOCK_SIZE)

    aes = AES.new(key)
    keys = []

    for i in range(BLOCKS_NUMBER):
        keys.append(aes.encrypt(int(int.from_bytes(IV, byteorder='big') + i).to_bytes(16, 'big', signed=False)))

    key_string = bytes()

    for i in range(BLOCKS_NUMBER):
        key_string += keys[i]

    return IV + xorb(message, key_string)


def ctr_decrypt(cipher: bytes, key: bytes) -> bytes:
    BLOCK_SIZE = 16
    BLOCKS_NUMBER = math.ceil(len(cipher) / BLOCK_SIZE) - 1

    aes = AES.new(key)
    IV = cipher[:BLOCK_SIZE]

    keys = []
    for i in range(BLOCKS_NUMBER):
        keys.append(aes.encrypt(int(int.from_bytes(IV, byteorder='big') + i).to_bytes(16, 'big', signed=False)))

    key_string = bytes()

    for i in range(BLOCKS_NUMBER):
        key_string += keys[i]

    return xorb(key_string, cipher[BLOCK_SIZE:])


# Test
# key = b'1234567890123456'
# message = 'I am a message, are you a message too? Great!'
# IV = urandom(16)

# cipher = ctr_encrypt(message.encode(), key, IV)

# print(ctr_decrypt(cipher, key).decode('ascii', 'replace'))

# Exercises

key = bytes.fromhex('140b41b22a29beb4061bda66b6747e14')

cipher = bytes.fromhex('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')

print('Question 1\n' + cbc_decrypt(cipher, key).decode('ascii', 'replace'))

cipher = bytes.fromhex('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')

print('Question 2\n' + cbc_decrypt(cipher, key).decode('ascii', 'replace'))

key = bytes.fromhex('36f18357be4dbd77f050515c73fcf9f2')

cipher = bytes.fromhex('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')

print('Question 3\n' + ctr_decrypt(cipher, key).decode('ascii', 'replace'))

cipher = bytes.fromhex('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')

print('Question 4\n' + ctr_decrypt(cipher, key).decode('ascii', 'replace'))