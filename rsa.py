import sys

from BitVector import BitVector


def gcd(a, b):
    while b != 0:
        temp = b
        b = a % b
        a = temp
    return a

def verify_primes_p_q(p, q):
    # Check p != q
    if p == q:
        return False

    # Convert prime to binary string
    p_binary = format(p, 'b')
    # Check two left-most bits are set.
    if len(p_binary) < 2 or p_binary[0] != '1' or p_binary[1] != '1':
        print("Failed check")
        return False

    # Convert prime to binary string
    q_binary = format(q, 'b')
    # Check two left-most bits are set.
    if len(q_binary) < 2 or q_binary[0] != '1' or q_binary[1] != '1':
        print("Failed check")
        return False

    # Check gcd(p-1, e) and gcd(q-1, e) is 1.
    return gcd(p - 1, e) == 1 and gcd(q - 1, e) == 1

def generate_primes_p_q(e):
    from PrimeGenerator import PrimeGenerator
    generator = PrimeGenerator(bits=128, debug=0, emod=e)

    p = 0
    q = 0
    while True:
        p = generator.findPrime()
        q = generator.findPrime()

        if verify_primes_p_q(p, q):
            # Found valid primes
            break;

    return (p, q)

# Encrypt function
def encrypt(message_blocks, e, p, q):
    n = p * q
    encrypted = [(m ** e) % n for m in message_blocks]
    return encrypted

def generate_private_key_d(e, p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    bv_modulus = BitVector(intVal = phi)
    bv = BitVector(intVal = e)
    bv_result = bv.multiplicative_inverse(bv_modulus)

    d = int(bv_result)
    return d

def decrypt(cipher_blocks, e, p, q):
    n = p * q
    d = generate_private_key_d(e, p, q)
    decrypted = [(c ** d) % n for c in cipher_blocks]
    print(decrypted)
    return decrypted

def decrypt_chinese_remainder(cipher_blocks, e, p, q):
    d = generate_private_key_d(e, p, q)
    d_p = d % (p - 1)
    d_q = d % (q - 1)

    bv_modulus = BitVector(intVal = p)
    q_bv = BitVector(intVal = q)
    q_inv = int(q_bv.multiplicative_inverse(bv_modulus))

    decrypted = []
    for c in cipher_blocks:
        m1 = (c ** d_p) % p
        m2 = (c ** d_q) % q
        h = (q_inv * (m1 - m2)) % p
        m = m2 + (h * q)
        decrypted.append(m)

    return decrypted

# Read from file
def read_message_blocks_from_file(filename):
    message_blocks = []

    with open(filename, 'r') as f:
        data = f.read()

        # 1 ascii character = 8 bits
        # 16 ascii characters = 128 bits
        newlines_to_append = 0
        if len(data) % 16 != 0:
            newlines_to_append = 16 - len(data) % 16

        # print("Remaining = " + str(newlines_to_append))

        newlines = ['\n' for i in range(newlines_to_append)]
        data_new = data + ''.join(newlines)

        # print("Aligned = {}".format(len(data_new) % 16))

        for i in range(0, len(data_new), 16):
            data_block = data_new[i:i + 16]
            val = 0
            for character in data_block:
                val = val << 8
                val = val + ord(character)
            message_blocks.append(val)
    return message_blocks

# Write to file
def write_message_blocks_to_file(filename, message_blocks):
    ascii_chars = []

    for block in message_blocks:
        block_chars = []
        for i in range(16):
            val = block & 255
            block = block >> 8

            block_chars.insert(0, chr(val))
        ascii_chars.extend(block_chars)

    output_string = ''.join(ascii_chars)
    with open(filename, 'w+') as f:
        f.write(output_string)


if __name__ == "__main__":
    # Default values for e and primes
    e = 65537
    (p, q) = (333007092316056427969827670300431419257, 282248422465210662819912414973987317823)

    # (p, q) = generate_primes_p_q(e)

    if len(sys.argv) != 4 or not (sys.argv[1] != '-e' or sys.argv[1] != '-d'):
        print("Generating primes")
        (p, q) = generate_primes_p_q(e)
        print("p = " + str(p))
        print("q = " + str(q))
        sys.exit(1)

    if sys.argv[1] == '-e':
        print("Encryption phase")
        message_file = sys.argv[2]
        output_file = sys.argv[3]

        blocks = read_message_blocks_from_file(message_file)
        print("Message blocks:")
        print(blocks)

        encrypted_blocks = encrypt(blocks, e, p, q)
        print("Encrypted blocks:")
        print(encrypted_blocks)

        write_message_blocks_to_file(output_file, encrypted_blocks)
    else:
        print("Decryption phase")
        cipher_file = sys.argv[2]
        decrypted_file = sys.argv[3]

        cipher_blocks = read_message_blocks_from_file(cipher_file)
        print("Cipher blocks:")
        print(cipher_blocks)

        # decrypted_blocks = decrypt(cipher_blocks, e, p, q)
        decrypted_blocks = decrypt_chinese_remainder(cipher_blocks, e, p, q)
        print("Decrypted blocks:")
        print(decrypted_blocks)

        write_message_blocks_to_file(decrypted_file, decrypted_blocks)
