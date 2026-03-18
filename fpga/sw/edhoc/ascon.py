#!/usr/bin/env python3

"""
Implementation of Ascon, an authenticated cipher and hash function
NIST SP 800-232
https://ascon.iaik.tugraz.at/
"""

# Debug control flags
debug = True                    # Enable/disable major operation state printing
debugpermutation = True         # Enable/disable detailed permutation round printing

def set_debug_level(level):
    """
    Set debug level for Ascon operations.
    level: 0 = No debug output
           1 = Major operations only (debug=True, debugpermutation=False)
           2 = Full debug with all permutation details (debug=True, debugpermutation=True)
    """
    global debug, debugpermutation
    if level == 0:
        debug = False
        debugpermutation = False
    elif level == 1:
        debug = True
        debugpermutation = False
    elif level == 2:
        debug = True
        debugpermutation = True
    else:
        print(f"Invalid debug level {level}. Use 0, 1, or 2.")

def print_state_summary(S, description=""):
    """Print state in a compact format for comparison with hardware"""
    print(f" {description}")
    print(" ".join([f"{s:016x}" for s in S]))

# === Ascon hash/xof ===

def ascon_hash(message, variant="Ascon-Hash256", hashlength=32, customization=b""): 
    """
    Ascon hash function and extendable-output function.
    message: a bytes object of arbitrary length
    variant: "Ascon-Hash256" (with 256-bit output for 128-bit security), "Ascon-XOF128", or "Ascon-CXOF128" (both with arbitrary output length, security=min(128, bitlen/2))
    hashlength: the requested output bytelength (must be 32 for variant "Ascon-Hash256"; can be arbitrary for Ascon-XOF128, but should be >= 32 for 128-bit security)
    customization: a bytes object of at most 256 bytes specifying the customization string (only for Ascon-CXOF128)
    returns a bytes object containing the hash tag
    """
    versions = {"Ascon-Hash256": 2,
                "Ascon-XOF128": 3,
                "Ascon-CXOF128": 4}
    assert variant in versions.keys()
    if variant == "Ascon-Hash256": assert hashlength == 32
    if variant == "Ascon-CXOF128": assert len(customization) <= 256
    else: assert len(customization) == 0
    a = b = 12 # rounds
    rate = 8 # bytes
    taglen = 256 if variant == "Ascon-Hash256" else 0
    customize = True if variant == "Ascon-CXOF128" else False

    # Initialization
    iv = to_bytes([versions[variant], 0, (b<<4) + a]) + int_to_bytes(taglen, 2) + to_bytes([rate, 0, 0])
    S = bytes_to_state(iv + zero_bytes(32))
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, 12)
    if debug: printstate(S, "initialization:")

    # Customization
    if customize: 
        z_padding = to_bytes([0x01]) + zero_bytes(rate - (len(customization) % rate) - 1)
        z_length = int_to_bytes(len(customization)*8, 8)
        z_padded = z_length + customization + z_padding

        # customization blocks 0,...,m
        for block in range(0, len(z_padded), rate):
            S[0] ^= bytes_to_int(z_padded[block:block+rate])
            ascon_permutation(S, 12)
        if debug: printstate(S, "customization:")

    # Message Processing (Absorbing)
    m_padding = to_bytes([0x01]) + zero_bytes(rate - (len(message) % rate) - 1)
    m_padded = message + m_padding

    # message blocks 0,...,n
    for block in range(0, len(m_padded), rate):
        S[0] ^= bytes_to_int(m_padded[block:block+rate])
        ascon_permutation(S, 12)
    if debug: printstate(S, "process message:")

    # Finalization (Squeezing)
    H = b""
    while len(H) < hashlength:
        H += int_to_bytes(S[0], rate)
        ascon_permutation(S, 12)
    if debug: printstate(S, "finalization:")
    return H[:hashlength]


# === HMAC-ASCON ===

def hmac_ascon(key, message, hash_variant="Ascon-Hash256", hashlength=32):
    """
    HMAC construction using ASCON hash function.
    Follows RFC 2104 HMAC specification with ASCON as the underlying hash.
    
    HMAC-ASCON provides message authentication using the proven HMAC construction
    with ASCON's efficient hash functions. This combines the security guarantees
    of HMAC with ASCON's performance advantages.
    
    Construction: HMAC-ASCON(K,M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))
    where H is the specified ASCON hash variant.
    
    Security: Inherits the security properties of both HMAC and the underlying
    ASCON hash function. Provides 128-bit security when using appropriate
    key lengths and output sizes.
    
    key: a bytes object of arbitrary length (will be hashed if > block_size)
    message: a bytes object of arbitrary length
    hash_variant: "Ascon-Hash256", "Ascon-XOF128", or "Ascon-CXOF128"
    hashlength: output length in bytes (32 for Hash256, arbitrary for XOF variants)
    returns: HMAC tag as bytes object
    """
    # Only Ascon-Hash256 is supported
    assert hash_variant == "Ascon-Hash256"
    assert hashlength == 32
    block_size = 64  # ASCON-Hash block size in bytes
    
    # HMAC padding constants
    ipad = 0x36
    opad = 0x5C
    
    # Key preprocessing: hash key if longer than block size
    if len(key) > block_size:
        key = ascon_hash(key, hash_variant, 32 if hash_variant == "Ascon-Hash256" else 64)
        print(f"Key hashed to {len(key)} bytes")
        print(f" Hashed key: {key.hex()}")
    
    # Pad key to block size
    if len(key) < block_size:
        key = key + zero_bytes(block_size - len(key))
    
    # Create inner and outer padded keys
    key_ipad = bytes([k ^ ipad for k in key])
    key_opad = bytes([k ^ opad for k in key])
    print(f"key opad: {key_opad.hex()}")
    
    # HMAC computation: H(K_opad || H(K_ipad || message))
    inner_hash = ascon_hash(key_ipad + message, "Ascon-Hash256", 32)
    print(f" HMAC-ASCON inner hash: {inner_hash.hex()}")
    hmac_result = ascon_hash(key_opad + inner_hash, "Ascon-Hash256", 32)
    print(f" HMAC-ASCON outer hash: {hmac_result.hex()}")
    
    if debug:
        print(f" HMAC-ASCON computation:")
        print(f"   Key length: {len(key)} bytes")
        print(f"   Message length: {len(message)} bytes")
        print(f"   Hash variant: {hash_variant}")
        print(f"   Output length: {hashlength} bytes")
    
    return hmac_result


# === Ascon MAC/PRF ===

def ascon_mac(key, message, variant="Ascon-Mac", taglength=16): 
    """
    Ascon message authentication code (MAC) and pseudorandom function (PRF).
    key: a bytes object of size 16
    message: a bytes object of arbitrary length (<= 16 for "Ascon-PrfShort")
    variant: "Ascon-Mac" (128-bit output, arbitrarily long input), "Ascon-Prf" (arbitrarily long input and output), or "Ascon-PrfShort" (t-bit output for t<=128, m-bit input for m<=128)
    taglength: the requested output bytelength l/8 (must be <=16 for variants "Ascon-Mac" and "Ascon-PrfShort", arbitrary for "Ascon-Prf"; should be >= 16 for 128-bit security)
    returns a bytes object containing the authentication tag
    """
    assert variant in ["Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"]
    if variant == "Ascon-Mac": assert len(key) == 16 and taglength <= 16
    if variant == "Ascon-Prf": assert len(key) == 16
    if variant == "Ascon-PrfShort": assert len(key) == 16 and taglength <= 16 and len(message) <= 16
    a = b = 12  # rounds
    msgblocksize = 32 # bytes (input rate for Mac, Prf)
    rate = 16 # bytes (output rate)

    # TODO update IVs to be consistent with NIST format

    if variant == "Ascon-PrfShort":
        # Initialization + Message Processing (Absorbing)
        IV = to_bytes([len(key) * 8, len(message)*8, a + 64, taglength * 8]) + zero_bytes(4)
        S = bytes_to_state(IV + key + message + zero_bytes(16 - len(message)))
        if debug: printstate(S, "initial value:")

        ascon_permutation(S, a)
        if debug: printstate(S, "process message:")

        # Finalization (Squeezing)
        T = int_to_bytes(S[3] ^ bytes_to_int(key[0:8]), 8) + int_to_bytes(S[4] ^ bytes_to_int(key[8:16]), 8)
        return T[:taglength]

    else: # Ascon-Prf, Ascon-Mac
        # Initialization
        if variant == "Ascon-Mac": tagspec = int_to_bytes(16*8, 4)
        if variant == "Ascon-Prf": tagspec = int_to_bytes(0*8, 4)
        S = bytes_to_state(to_bytes([len(key) * 8, rate * 8, a + 128, a-b]) + tagspec + key + zero_bytes(16))
        if debug: printstate(S, "initial value:")

        ascon_permutation(S, a)
        if debug: printstate(S, "initialization:")

        # Message Processing (Absorbing)
        m_padding = to_bytes([0x01]) + zero_bytes(msgblocksize - (len(message) % msgblocksize) - 1)
        m_padded = message + m_padding

        # first s-1 blocks
        for block in range(0, len(m_padded) - msgblocksize, msgblocksize):
            S[0] ^= bytes_to_int(m_padded[block:block+8])     # msgblocksize=32 bytes
            S[1] ^= bytes_to_int(m_padded[block+8:block+16])
            S[2] ^= bytes_to_int(m_padded[block+16:block+24])
            S[3] ^= bytes_to_int(m_padded[block+24:block+32])
            ascon_permutation(S, b)
        # last block
        block = len(m_padded) - msgblocksize
        S[0] ^= bytes_to_int(m_padded[block:block+8])     # msgblocksize=32 bytes
        S[1] ^= bytes_to_int(m_padded[block+8:block+16])
        S[2] ^= bytes_to_int(m_padded[block+16:block+24])
        S[3] ^= bytes_to_int(m_padded[block+24:block+32])
        S[4] ^= 1
        if debug: printstate(S, "process message:")

        # Finalization (Squeezing)
        T = b""
        ascon_permutation(S, a)
        while len(T) < taglength:
            T += int_to_bytes(S[0], 8)  # rate=16
            T += int_to_bytes(S[1], 8)
            ascon_permutation(S, b)
        if debug: printstate(S, "finalization:")
        return T[:taglength]


# === Ascon AEAD encryption and decryption ===

def ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-AEAD128"): 
    """
    Ascon encryption.
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    plaintext: a bytes object of arbitrary length
    variant: "Ascon-AEAD128"
    returns a bytes object of length len(plaintext)+16 containing the ciphertext and tag
    """
    versions = {"Ascon-AEAD128": 1}
    assert variant in versions.keys()
    assert len(key) == 16 and len(nonce) == 16
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8   # bits
    a = 12   # rounds
    b = 8    # rounds
    rate = 16   # bytes

    ascon_initialize(S, k, rate, a, b, versions[variant], key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return (ciphertext, tag)


def ascon_decrypt(key, nonce, associateddata, ciphertext, variant="Ascon-AEAD128"):
    """
    Ascon decryption.
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16 (must not repeat for the same key!)
    associateddata: a bytes object of arbitrary length
    ciphertext: a bytes object of arbitrary length (also contains tag)
    variant: "Ascon-AEAD128"
    returns a bytes object containing the plaintext or None if verification fails
    """
    versions = {"Ascon-AEAD128": 1}
    assert variant in versions.keys()
    assert len(key) == 16 and len(nonce) == 16 and len(ciphertext) >= 16
    S = [0, 0, 0, 0, 0]
    k = len(key) * 8 # bits
    a = 12  # rounds
    b = 8   # rounds
    rate = 16   # bytes

    ascon_initialize(S, k, rate, a, b, versions[variant], key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-16])
    tag = ascon_finalize(S, rate, a, key)
    if tag == ciphertext[-16:]:
        return plaintext
    else:
        return None


# === Ascon AEAD building blocks ===

def ascon_initialize(S, k, rate, a, b, version, key, nonce):
    """
    Ascon initialization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    k: key size in bits
    rate: block size in bytes (16 for Ascon-AEAD128)
    a: number of initialization/finalization rounds for permutation
    b: number of intermediate rounds for permutation
    version: 1 (for Ascon-AEAD128)
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    nonce: a bytes object of size 16
    returns nothing, updates S
    """
    taglen = 128
    iv = to_bytes([version, 0, (b<<4) + a]) + int_to_bytes(taglen, 2) + to_bytes([rate, 0, 0])
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv + key + nonce)
    if debug: printstate(S, "initial value:")

    ascon_permutation(S, a)

    zero_key = bytes_to_state(zero_bytes(40-len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]
    if debug: printstate(S, "initialization:")


def ascon_process_associated_data(S, b, rate, associateddata):
    """
    Ascon associated data processing phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    associateddata: a bytes object of arbitrary length
    returns nothing, updates S
    """
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded = associateddata + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block+8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block+8:block+16])

            ascon_permutation(S, b)

    S[4] ^= 1<<63
    if debug: printstate(S, "process associated data:")


def ascon_process_plaintext(S, b, rate, plaintext):
    """
    Ascon plaintext processing phase (during encryption) - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    plaintext: a bytes object of arbitrary length
    returns the ciphertext (without tag), updates S
    """
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x01]) + zero_bytes(rate-p_lastlen-1)
    p_padded = plaintext + p_padding

    # first t-1 blocks
    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        S[0] ^= bytes_to_int(p_padded[block:block+8])
        S[1] ^= bytes_to_int(p_padded[block+8:block+16])
        ciphertext += (int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8))
        ascon_permutation(S, b)

    # last block t
    block = len(p_padded) - rate
    S[0] ^= bytes_to_int(p_padded[block:block+8])
    S[1] ^= bytes_to_int(p_padded[block+8:block+16])
    ciphertext += (int_to_bytes(S[0], 8)[:min(8,p_lastlen)] + int_to_bytes(S[1], 8)[:max(0,p_lastlen-8)])
    if debug: printstate(S, "process plaintext:")
    return ciphertext


def ascon_process_ciphertext(S, b, rate, ciphertext):
    """
    Ascon ciphertext processing phase (during decryption) - internal helper function. 
    S: Ascon state, a list of 5 64-bit integers
    b: number of intermediate rounds for permutation
    rate: block size in bytes (16 for Ascon-AEAD128)
    ciphertext: a bytes object of arbitrary length
    returns the plaintext, updates S
    """
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)

    # first t-1 blocks
    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
        plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))
        S[0] = Ci[0]
        S[1] = Ci[1]
        ascon_permutation(S, b)

    # last block t
    block = len(c_padded) - rate
    c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate-c_lastlen-1)
    c_mask = zero_bytes(c_lastlen) + ff_bytes(rate-c_lastlen)
    Ci = (bytes_to_int(c_padded[block:block+8]), bytes_to_int(c_padded[block+8:block+16]))
    plaintext += (int_to_bytes(S[0] ^ Ci[0], 8) + int_to_bytes(S[1] ^ Ci[1], 8))[:c_lastlen]
    S[0] = (S[0] & bytes_to_int(c_mask[0:8]))  ^ Ci[0] ^ bytes_to_int(c_padx[0:8])
    S[1] = (S[1] & bytes_to_int(c_mask[8:16])) ^ Ci[1] ^ bytes_to_int(c_padx[8:16])
    if debug: printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S, rate, a, key):
    """
    Ascon finalization phase - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rate: block size in bytes (16 for Ascon-AEAD128)
    a: number of initialization/finalization rounds for permutation
    key: a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
    returns the tag, updates S
    """
    assert len(key) == 16
    S[rate//8+0] ^= bytes_to_int(key[0:8])
    S[rate//8+1] ^= bytes_to_int(key[8:16])

    ascon_permutation(S, a)

    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag


# === Ascon permutation ===

def ascon_permutation(S, rounds=1):
    """
    Ascon core permutation for the sponge construction - internal helper function.
    S: Ascon state, a list of 5 64-bit integers
    rounds: number of rounds to perform
    returns nothing, updates S
    """
    assert rounds <= 12
    if debugpermutation: 
        print(f"\n=== PERMUTATION START ({rounds} rounds) ===")
        printwords(S, "permutation input:")
    for r in range(12-rounds, 12):
        # if debugpermutation: print(f"\n--- Round {r} ---")
        # --- add round constants ---
        S[2] ^= (0xf0 - r*0x10 + r*0x1)
        # if debugpermutation: printwords(S, "round constant addition:")
        # --- substitution layer ---
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i+1)%5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0XFFFFFFFFFFFFFFFF
        # if debugpermutation: printwords(S, "substitution layer:")
        # --- linear diffusion layer ---
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)
        # if debugpermutation: printwords(S, "linear diffusion layer:")
    if debugpermutation: 
        print("=== PERMUTATION END ===")
        printstate(S, "final permutation state:")


# === helper functions ===

def get_random_bytes(num):
    import os
    return to_bytes(os.urandom(num))

def zero_bytes(n):
    return n * b"\x00"

def ff_bytes(n):
    return n * b"\xFF"

def to_bytes(l): # where l is a list or bytearray or bytes
    return bytes(bytearray(l))

def bytes_to_int(bytes):
    return sum([bi << (i*8) for i, bi in enumerate(to_bytes(bytes))])

def bytes_to_state(bytes):
    return [bytes_to_int(bytes[8*w:8*(w+1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> (i * 8)) % 256 for i in range(nbytes)])

def rotr(val, r):
    return (val >> r) | ((val & (1<<r)-1) << (64-r))

def bytes_to_hex(b):
    return b.hex()
    #return "".join(x.encode('hex') for x in b)

def printstate(S, description=""):
    print(" " + description)
    print(" ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S, description=""):
    print(" " + description)
    print("\n".join(["  x{i}= {s:016x}".format(**locals()) for i, s in enumerate(S)]))


# === some demo if called directly ===

def demo_print(data):
    maxlen = max([len(text) for (text, val) in data])
    for text, val in data:
        print("{text}:{align} 0x{val} ({length} bytes)".format(text=text, align=((maxlen - len(text)) * " "), val=bytes_to_hex(val), length=len(val)))

def demo_aead(variant="Ascon-AEAD128"):
    print("=== demo encryption using {variant} ===".format(variant=variant))
    # Use the exact test parameters from hardware testbench
    key = bytes.fromhex('0f0e0d0c0b0a09080706050403020100')
    nonce = bytes.fromhex('1f1e1d1c1b1a19181716151413121110')
   
    associateddata = b"FifteenBytesAD!"
    plaintext = b"FifteenBytesPT!"
    
    # Show data broken down into 64-bit blocks (as in hardware testbench)
    print("\n=== Data Breakdown into 64-bit blocks ===")
    
    # Associated Data breakdown
    if associateddata:
        print("Associated Data: \"{}\" ({} bytes)".format(associateddata.decode(), len(associateddata)))
        for i in range(0, len(associateddata), 16):
            block_num = i // 16
            left_part = associateddata[i:i+8]
            right_part = associateddata[i+8:i+16]
            print("  Block {}: {} + {}".format(
                block_num, 
                left_part.hex() if left_part else "0000000000000000",
                right_part.hex() if right_part else "0000000000000000"
            ))
    else:
        print("Associated Data: (empty)")
    
    # Plaintext breakdown
    if plaintext:
        print("\nPlaintext: \"{}\" ({} bytes)".format(plaintext.decode(), len(plaintext)))
        for i in range(0, len(plaintext), 16):
            block_num = i // 16
            left_part = plaintext[i:i+8]
            right_part = plaintext[i+8:i+16]
            left_str = left_part.decode('utf-8', errors='replace') if left_part else ""
            right_str = right_part.decode('utf-8', errors='replace') if right_part else ""
            print("  Block {}: \"{}\" + \"{}\"".format(block_num, left_str, right_str))
            print("  Hex:     {} + {}".format(
                left_part.hex() if left_part else "0000000000000000",
                right_part.hex() if right_part else "0000000000000000"
            ))
    else:
        print("\nPlaintext: (empty)")
    
    # Verilog format output
    print("\n=== Verilog Format ===")
    
    # Associated Data in Verilog format
    if associateddata:
        ad_comment = associateddata.decode()[:50] + "..." if len(associateddata.decode()) > 50 else associateddata.decode()
        print("    // Associated Data: \"{}\" ({} bytes)".format(ad_comment, len(associateddata)))
        # Calculate total blocks needed
        total_ad_blocks = (len(associateddata) + 15) // 16
        for i in range(0, len(associateddata), 16):
            block_num = i // 16
            left_part = associateddata[i:i+8]
            right_part = associateddata[i+8:i+16]
            # Pad hex values to 16 characters (8 bytes)
            left_hex = left_part.hex().ljust(16, '0') if left_part else "0000000000000000"
            right_hex = right_part.hex().ljust(16, '0') if right_part else "0000000000000000"
            left_str = left_part.decode('utf-8', errors='replace') if left_part else ""
            right_str = right_part.decode('utf-8', errors='replace') if right_part else ""
            
            # Show byte sizes only for the last block
            if block_num == total_ad_blocks - 1:
                left_bytes = len(left_part)
                right_bytes = len(right_part) 
                total_bytes = left_bytes + right_bytes
                comment = "\"{}{}\" ({} bytes: {}+{})".format(left_str, right_str, total_bytes, left_bytes, right_bytes)
            else:
                comment = "\"{}{}\"".format(left_str, right_str)
            
            print("    associated_data[{}] = {{64'h{}, 64'h{}}}; // {}".format(
                block_num, left_hex, right_hex, comment
            ))
    
    # Plaintext in Verilog format  
    if plaintext:
        pt_comment = plaintext.decode()[:50] + "..." if len(plaintext.decode()) > 50 else plaintext.decode()
        print("    // Plaintext: \"{}\" ({} bytes)".format(pt_comment, len(plaintext)))
        # Calculate total blocks needed
        total_pt_blocks = (len(plaintext) + 15) // 16
        for i in range(0, len(plaintext), 16):
            block_num = i // 16
            left_part = plaintext[i:i+8]
            right_part = plaintext[i+8:i+16]
            # Pad hex values to 16 characters (8 bytes)
            left_hex = left_part.hex().ljust(16, '0') if left_part else "0000000000000000"
            right_hex = right_part.hex().ljust(16, '0') if right_part else "0000000000000000"
            left_str = left_part.decode('utf-8', errors='replace') if left_part else ""
            right_str = right_part.decode('utf-8', errors='replace') if right_part else ""
            
            # Show byte sizes only for the last block
            if block_num == total_pt_blocks - 1:
                left_bytes = len(left_part)
                right_bytes = len(right_part)
                total_bytes = left_bytes + right_bytes
                comment = "\"{}{}\" ({} bytes: {}+{})".format(left_str, right_str, total_bytes, left_bytes, right_bytes)
            else:
                comment = "\"{}{}\"".format(left_str, right_str)
            
            print("    plaintext_data[{}] = {{64'h{}, 64'h{}}}; // {}".format(
                block_num, left_hex, right_hex, comment
            ))
    
    (ciphertext, tag) = ascon_encrypt(key, nonce, associateddata, plaintext, variant)
    
    # Show plaintext/ciphertext in 128-bit blocks
    print("\n=== 128-bit Block Breakdown ===")
    
    # Plaintext blocks
    if plaintext:
        print("Plaintext blocks (128-bit each):")
        for i in range(0, len(plaintext), 16):
            block_num = i // 16
            block_data = plaintext[i:i+16]
            if len(block_data) < 16:
                # Pad partial block with zeros for display
                block_data = block_data + b'\x00' * (16 - len(block_data))
            
            # Split into two 64-bit parts
            left_64 = block_data[0:8]
            right_64 = block_data[8:16]
            
            # Calculate actual bytes (before padding)
            actual_bytes = min(16, len(plaintext) - i)
            left_actual = min(8, actual_bytes)
            right_actual = max(0, actual_bytes - 8)
            
            # Show block info
            if actual_bytes == 16:
                size_info = ""
            else:
                size_info = " ({} bytes: {}+{})".format(actual_bytes, left_actual, right_actual)
            
            print("  Block {}: {} {}{}".format(
                block_num, 
                left_64.hex(),
                right_64.hex(),
                size_info
            ))
    
    # Ciphertext blocks
    if ciphertext:
        print("Ciphertext blocks (128-bit each):")
        for i in range(0, len(ciphertext), 16):
            block_num = i // 16
            block_data = ciphertext[i:i+16]
            if len(block_data) < 16:
                # Pad partial block with zeros for display
                block_data = block_data + b'\x00' * (16 - len(block_data))
            
            # Split into two 64-bit parts
            left_64 = block_data[0:8]
            right_64 = block_data[8:16]
            
            # Calculate actual bytes (before padding)
            actual_bytes = min(16, len(ciphertext) - i)
            left_actual = min(8, actual_bytes)
            right_actual = max(0, actual_bytes - 8)
            
            # Show block info
            if actual_bytes == 16:
                size_info = ""
            else:
                size_info = " ({} bytes: {}+{})".format(actual_bytes, left_actual, right_actual)
            
            print("  Block {}: {} {}{}".format(
                block_num, 
                left_64.hex(),
                right_64.hex(),
                size_info
            ))
    
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext + tag, variant)
    if receivedplaintext == None: print("verification failed!")
       
    demo_print([("key", key),
                ("nonce", nonce),
                ("plaintext", plaintext),
                ("ass.data", associateddata),
                ("ciphertext", ciphertext),
                ("tag", tag),
                # ("received", receivedplaintext),
               ])

def demo_hash(variant="Ascon-Hash256", hashlength=32):
    assert variant in ["Ascon-Hash256", "Ascon-XOF128", "Ascon-CXOF128"]
    print("=== demo hash using {variant} ===".format(variant=variant))

    message = bytes.fromhex("04075820_9dc7755b_e724fc2b_04bf1d55_aea556c5_dfc13627_97749b0d_ecff751e_70764f48_2d")
    customization = b"custom" if variant == "Ascon-CXOF128" else b""
    tag = ascon_hash(message, variant, hashlength, customization)

    demo_print([("message", message), ("customization", customization), ("tag", tag)])

def demo_mac(variant="Ascon-Mac", taglength=16):
    # TODO rename variants to be consistent with NIST format
    assert variant in ["Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"]
    print("=== demo MAC using {variant} ===".format(variant=variant))

    key = get_random_bytes(16)
    message = b"ascon"
    tag = ascon_mac(key, message, variant)

    demo_print([("key", key), ("message", message), ("tag", tag)])

def hmac_ascon_verify(key, message, tag, hash_variant="Ascon-Hash256"):
    """
    Verify an HMAC-ASCON tag.
    
    key: the secret key used for HMAC
    message: the message that was authenticated
    tag: the tag to verify (bytes object)
    hash_variant: the ASCON hash variant used
    returns: True if tag is valid, False otherwise
    """
    # Only Ascon-Hash256 is supported
    expected_tag = hmac_ascon(key, message, "Ascon-Hash256", 32)
    return expected_tag == tag


def demo_hmac_ascon(hash_variant="Ascon-Hash256", hashlength=32):
    """Demo HMAC-ASCON with comprehensive correctness verification"""
    print("=== HMAC-ASCON Correctness Verification using Ascon-Hash256 ===")
    
    # Test case 1: Short key and message
    print("\n--- Test Case 1: Short key and message ---")
    key1 = b"short_key"
    message1 = b"Hello, ASCON HMAC!"
    tag1 = hmac_ascon(key1, message1, "Ascon-Hash256", 32)
    demo_print([("key", key1), ("message", message1), ("HMAC tag", tag1)])


# def test_hardware_testbench_vectors():
#     """
#     Test HMAC-ASCON using the exact same data patterns as the hardware testbench.
#     This creates the same key and message data as the Verilog testbench for verification.
#     """
#     print("=== HARDWARE TESTBENCH VECTOR TEST ===")
    
#     # Replicate the Verilog testbench key generation:
#     # for (i = 0; i < 8; i = i + 1) 
#     #   key_data[i] = 64'hAABBCCDD00000000 + i;
    
#     key_chunks = []
#     for i in range(8):
#         # 64'hAABBCCDD00000000 + i in big-endian byte order (matching hardware)
#         chunk_value = 0xAABBCCDD00000000 + i
#         # Convert to 8 bytes in big-endian order (Verilog-style)
#         chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
#         key_chunks.append(chunk_bytes)
    
#     # Concatenate all key chunks to form 64-byte key
#     key = b''.join(key_chunks)
    
#     # Replicate the Verilog testbench message generation:
#     # for (i = 0; i < 4; i = i + 1) 
#     #   message_data[i] = 64'h1122334400000000 + i;
    
#     message_chunks = []
#     for i in range(4):
#         # 64'h1122334400000000 + i in big-endian byte order (matching hardware)
#         chunk_value = 0x1122334400000000 + i
#         # Convert to 8 bytes in big-endian order (Verilog-style)
#         chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
#         message_chunks.append(chunk_bytes)
    
#     # Concatenate all message chunks to form 32-byte message
#     message = b''.join(message_chunks)
    
#     print(f"\n--- Hardware Testbench Data ---")
#     print(f"Key (64 bytes):")
#     for i, chunk in enumerate(key_chunks):
#         chunk_value = 0xAABBCCDD00000000 + i
#         print(f"  key_data[{i}] = {chunk.hex()} (64'h{chunk_value:016x})")
    
#     print(f"\nMessage (32 bytes):")
#     for i, chunk in enumerate(message_chunks):
#         chunk_value = 0x1122334400000000 + i
#         print(f"  message_data[{i}] = {chunk.hex()} (64'h{chunk_value:016x})")
    
#     print(f"\nConcatenated key: {key.hex()}")
#     print(f"Concatenated message: {message.hex()}")
    
#     # Compute HMAC-ASCON
#     print(f"\n--- HMAC-ASCON Computation ---")
#     tag = hmac_ascon(key, message, "Ascon-Hash256", 32)
    
#     print(f"HMAC-ASCON-256 tag: {tag.hex()}")
    
#     # # Verify consistency
#     # tag2 = hmac_ascon(key, message, "Ascon-Hash256", 32)
#     # consistent = (tag == tag2)
#     # print(f"Consistency check: {'✓ PASS' if consistent else '✗ FAIL'}")
    
#     # # Display in hardware-friendly format
#     # print(f"\n--- Hardware Expected Results ---")
#     # print(f"Expected tag_out[127:0] = 128'h{tag[:16].hex()}")
#     # print(f"Expected tag_out_high[127:0] = 128'h{tag[16:].hex()}")
    
#     # # Split into 64-bit chunks for easier hardware comparison
#     # print(f"\n--- 64-bit Chunks for Hardware Verification ---")
#     # for i in range(0, 32, 8):
#     #     chunk = tag[i:i+8]
#     #     print(f"tag_chunk[{i//8}] = 64'h{chunk.hex()}")
    
#     return tag


# def test_verilog_pattern_detailed():
#     """
#     Detailed test showing exactly how the Verilog patterns translate to Python bytes
#     """
#     print("=== DETAILED VERILOG PATTERN TRANSLATION ===")
    
#     print("\n--- Key Pattern Analysis ---")
#     base_key = 0xAABBCCDD00000000
#     print(f"Base key pattern: 64'h{base_key:016x}")
    
#     for i in range(8):
#         chunk_value = base_key + i
#         # Show both big-endian (Verilog-style) and little-endian (Python bytes)
#         chunk_be = chunk_value.to_bytes(8, byteorder='big')
#         chunk_le = chunk_value.to_bytes(8, byteorder='little')
        
#         print(f"key_data[{i}]:")
#         print(f"  Verilog: 64'h{chunk_value:016x}")
#         print(f"  Big-endian bytes: {chunk_be.hex()}")
#         print(f"  Little-endian bytes: {chunk_le.hex()}")
#         print(f"  ASCII interpretation: {chunk_be}")
    
#     print("\n--- Message Pattern Analysis ---")
#     base_msg = 0x1122334400000000
#     print(f"Base message pattern: 64'h{base_msg:016x}")
    
#     for i in range(4):
#         chunk_value = base_msg + i
#         chunk_be = chunk_value.to_bytes(8, byteorder='big')
#         chunk_le = chunk_value.to_bytes(8, byteorder='little')
        
#         print(f"message_data[{i}]:")
#         print(f"  Verilog: 64'h{chunk_value:016x}")
#         print(f"  Big-endian bytes: {chunk_be.hex()}")
#         print(f"  Little-endian bytes: {chunk_le.hex()}")
    
#     # Test with big-endian (more natural for Verilog comparison)
#     print(f"\n--- HMAC Test with Big-Endian Byte Order ---")
    
#     key_chunks_be = []
#     for i in range(4):
#         chunk_value = 0xAABBCCDD00000000 + i
#         chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
#         key_chunks_be.append(chunk_bytes)
    
#     message_chunks_be = []
#     for i in range(4):
#         chunk_value = 0x1122334400000000 + i
#         chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
#         message_chunks_be.append(chunk_bytes)
    
#     key_be = b''.join(key_chunks_be)
#     message_be = b''.join(message_chunks_be)
    
#     print(f"Key (big-endian): {key_be.hex()}")
#     print(f"Message (big-endian): {message_be.hex()}")
    
#     tag_be = hmac_ascon(key_be, message_be, "Ascon-Hash256", 32)
#     print(f"HMAC tag (big-endian input): {tag_be.hex()}")
    
#     return tag_be
    
    # # Verify tag validation
    # valid1 = hmac_ascon_verify(key1, message1, tag1)
    # print(f"✓ Tag verification: {'PASS' if valid1 else 'FAIL'}")
    
    # # Test case 2: Long key (will be hashed)
    # print("\n--- Test Case 2: Long key (>64 bytes, will be hashed) ---")
    # key2 = b"This is a very long key that exceeds the block size and will be hashed before HMAC processing" + b"x" * 50
    # message2 = b"Message with long key"
    # tag2 = hmac_ascon(key2, message2, "Ascon-Hash256", 32)
    # demo_print([("long key", key2[:50] + b"...[truncated]"), ("message", message2), ("HMAC tag", tag2)])
    
    # # Verify long key handling
    # valid2 = hmac_ascon_verify(key2, message2, tag2)
    # print(f"✓ Long key verification: {'PASS' if valid2 else 'FAIL'}")
    
    # # Test case 3: RFC test vector style
    # print("\n--- Test Case 3: RFC-style test vector ---")
    # key3 = bytes([0x0b] * 20)  # 20 bytes of 0x0b
    # message3 = b"Hi There"
    # tag3 = hmac_ascon(key3, message3, "Ascon-Hash256", 32)
    # demo_print([("test key", key3), ("test message", message3), ("HMAC tag", tag3)])
    
    # # Verify RFC-style test
    # valid3 = hmac_ascon_verify(key3, message3, tag3)
    # print(f"✓ RFC vector verification: {'PASS' if valid3 else 'FAIL'}")
    
    # # Test case 4: Empty message
    # print("\n--- Test Case 4: Empty message ---")
    # key4 = b"test_key_for_empty_msg"
    # message4 = b""
    # tag4 = hmac_ascon(key4, message4, "Ascon-Hash256", 32)
    # demo_print([("key", key4), ("empty message", message4), ("HMAC tag", tag4)])
    
    # # Verify empty message handling
    # valid4 = hmac_ascon_verify(key4, message4, tag4)
    # print(f"✓ Empty message verification: {'PASS' if valid4 else 'FAIL'}")
    
    # # Test case 5: Consistency check
    # print("\n--- Test Case 5: Consistency verification ---")
    # test_key = b"consistency_test"
    # test_msg = b"Same input should produce same output"
    # tag_a = hmac_ascon(test_key, test_msg, "Ascon-Hash256", 32)
    # tag_b = hmac_ascon(test_key, test_msg, "Ascon-Hash256", 32)
    # consistency = (tag_a == tag_b)
    # print(f"✓ Consistency check: {'PASS' if consistency else 'FAIL'}")
    
    # # Test case 6: Tamper detection
    # print("\n--- Test Case 6: Tamper detection ---")
    # original_msg = b"Original message"
    # tampered_msg = b"Tampered message"
    # original_tag = hmac_ascon(test_key, original_msg, "Ascon-Hash256", 32)
    
    # # Try to verify tampered message with original tag
    # tamper_valid = hmac_ascon_verify(test_key, tampered_msg, original_tag)
    # print(f"✓ Tamper detection: {'PASS' if not tamper_valid else 'FAIL'}")
    
    # # Test case 7: Wrong key detection  
    # print("\n--- Test Case 7: Wrong key detection ---")
    # correct_key = b"correct_key"
    # wrong_key = b"wrong_key"
    # test_message = b"Test message"
    # correct_tag = hmac_ascon(correct_key, test_message, "Ascon-Hash256", 32)
    
    # # Try to verify with wrong key
    # wrong_key_valid = hmac_ascon_verify(wrong_key, test_message, correct_tag)
    # print(f"✓ Wrong key detection: {'PASS' if not wrong_key_valid else 'FAIL'}")
    
    # # Summary
    # all_tests = [valid1, valid2, valid3, valid4, consistency, not tamper_valid, not wrong_key_valid]
    # passed = sum(all_tests)
    # total = len(all_tests)
    
    # print(f"\n{'='*50}")
    # print(f"VERIFICATION SUMMARY: {passed}/{total} tests passed")
    # if passed == total:
    #     print("🎉 ALL TESTS PASSED - HMAC-ASCON implementation is CORRECT!")
    # else:
    #     print("❌ Some tests failed - check implementation")
    # print(f"{'='*50}")
    
    # return passed == total


def generate_hardware_test_sequence(key_size_bytes, message_size_bytes=32, key_base=0xAABBCCDD00000000, message_base=0x1122334400000000):
    """
    Generate the exact sequence of 64-bit data chunks that should be sent to the hardware
    for HMAC testing, along with control signals.
    
    This is specifically designed to help create hardware testbench sequences that match
    the streaming interface requirements where keys are fed in 64-bit chunks.
    
    Args:
        key_size_bytes: Size of key in bytes
        message_size_bytes: Size of message in bytes  
        key_base: Base value for key pattern generation
        message_base: Base value for message pattern generation
    
    Returns:
        dict: {
            'key_sequence': [(chunk_64bit_hex, valid_bytes, is_last_chunk), ...],
            'message_sequence': [(chunk_64bit_hex, valid_bytes, is_last_chunk), ...],
            'expected_tag': 'hex_string',
            'hmac_case': 'A'|'B'|'C',
            'key_size_bytes': int,
            'message_size_bytes': int
        }
    """
    
    # Generate the test patterns first
    key, message, tag, key_chunks, msg_chunks = generate_hmac_test_patterns(
        key_size_bytes, message_size_bytes, key_base, message_base
    )
    
    # Determine HMAC case
    if key_size_bytes > 64:
        hmac_case = "B"
    elif key_size_bytes == 64:
        hmac_case = "A"
    else:
        hmac_case = "C"
    
    # Generate key sequence (always in 64-bit chunks for hardware interface)
    key_sequence = []
    key_bytes_processed = 0
    chunk_index = 0
    
    while key_bytes_processed < key_size_bytes:
        remaining_key_bytes = key_size_bytes - key_bytes_processed
        
        if remaining_key_bytes >= 8:
            # Full 8-byte chunk
            chunk_bytes = key[key_bytes_processed:key_bytes_processed + 8]
            valid_bytes = 8
            key_bytes_processed += 8
        else:
            # Partial chunk - pad with zeros to make 8 bytes for hardware interface
            chunk_bytes = key[key_bytes_processed:key_bytes_processed + remaining_key_bytes]
            chunk_bytes += b'\\x00' * (8 - len(chunk_bytes))  # Pad with zeros
            valid_bytes = remaining_key_bytes
            key_bytes_processed += remaining_key_bytes
        
        # Convert to 64-bit hex value
        chunk_64bit = int.from_bytes(chunk_bytes, byteorder='big')
        is_last_chunk = (key_bytes_processed >= key_size_bytes)
        
        key_sequence.append((f"{chunk_64bit:016x}", valid_bytes, is_last_chunk))
        chunk_index += 1
    
    # Generate message sequence
    message_sequence = []
    msg_bytes_processed = 0
    
    while msg_bytes_processed < message_size_bytes:
        remaining_msg_bytes = message_size_bytes - msg_bytes_processed
        
        if remaining_msg_bytes >= 8:
            # Full 8-byte chunk
            chunk_bytes = message[msg_bytes_processed:msg_bytes_processed + 8]
            valid_bytes = 8
            msg_bytes_processed += 8
        else:
            # Partial chunk - pad with zeros to make 8 bytes for hardware interface
            chunk_bytes = message[msg_bytes_processed:msg_bytes_processed + remaining_msg_bytes]
            chunk_bytes += b'\\x00' * (8 - len(chunk_bytes))  # Pad with zeros
            valid_bytes = remaining_msg_bytes
            msg_bytes_processed += remaining_msg_bytes
        
        # Convert to 64-bit hex value
        chunk_64bit = int.from_bytes(chunk_bytes, byteorder='big')
        is_last_chunk = (msg_bytes_processed >= message_size_bytes)
        
        message_sequence.append((f"{chunk_64bit:016x}", valid_bytes, is_last_chunk))
    
    result = {
        'key_sequence': key_sequence,
        'message_sequence': message_sequence,
        'expected_tag': tag.hex(),
        'hmac_case': hmac_case,
        'key_size_bytes': key_size_bytes,
        'message_size_bytes': message_size_bytes,
        'key_hex': key.hex(),
        'message_hex': message.hex()
    }
    
    # Print hardware-friendly format
    print(f"\n--- HARDWARE TEST SEQUENCE ---")
    print(f"HMAC Case {hmac_case}: Key size = {key_size_bytes} bytes, Message size = {message_size_bytes} bytes")
    print(f"\\nKey sequence ({len(key_sequence)} chunks):")
    for i, (chunk_hex, valid_bytes, is_last) in enumerate(key_sequence):
        last_flag = "LAST" if is_last else "    "
        print(f"  [{i:2d}] 64'h{chunk_hex} ({valid_bytes} bytes) {last_flag}")
    
    print(f"\\nMessage sequence ({len(message_sequence)} chunks):")
    for i, (chunk_hex, valid_bytes, is_last) in enumerate(message_sequence):
        last_flag = "LAST" if is_last else "    "
        print(f"  [{i:2d}] 64'h{chunk_hex} ({valid_bytes} bytes) {last_flag}")
    
    print(f"\\nExpected HMAC tag: {tag.hex()}")
    print(f"Expected tag (lower 128): {tag[:16].hex()}")
    print(f"Expected tag (upper 128): {tag[16:].hex()}")
    
    return result


def generate_hmac_test_patterns(key_size_bytes, message_size_bytes=32, key_base=0xAABBCCDD00000000, message_base=0x1122334400000000):
    """
    Generate configurable HMAC test patterns for hardware verification.
    
    This function creates test vectors with specific key and message sizes to test
    different HMAC cases:
    - Case A: key_size_bytes <= 64 (key used directly)
    - Case B: key_size_bytes > 64 (key gets hashed first)
    - Case C: key_size_bytes < 64 (key gets padded with zeros)
    
    Args:
        key_size_bytes: Size of key in bytes (can be any value, typically 16-128)
        message_size_bytes: Size of message in bytes (default 32)
        key_base: Base value for key pattern generation (default 0xAABBCCDD00000000)
        message_base: Base value for message pattern generation (default 0x1122334400000000)
    
    Returns:
        tuple: (key_bytes, message_bytes, hmac_tag, key_chunks, message_chunks)
    """
    print(f"=== HMAC TEST PATTERN GENERATION ===")
    print(f"Key size: {key_size_bytes} bytes")
    print(f"Message size: {message_size_bytes} bytes")
    
    # Determine HMAC case
    if key_size_bytes > 64:
        case = "B (Key > 64 bytes - will be hashed)"
    elif key_size_bytes == 64:
        case = "A (Key = 64 bytes - used directly)"
    else:
        case = "C (Key < 64 bytes - will be padded)"
    
    print(f"HMAC Case: {case}")
    
    # Generate key chunks (8 bytes each)
    key_chunks = []
    full_chunks = key_size_bytes // 8
    remaining_bytes = key_size_bytes % 8
    
    # Full 8-byte chunks
    for i in range(full_chunks):
        chunk_value = key_base + i
        chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
        key_chunks.append(chunk_bytes)
    
    # Partial chunk if needed
    if remaining_bytes > 0:
        chunk_value = key_base + full_chunks
        # Take only the needed bytes from the 8-byte chunk
        full_chunk = chunk_value.to_bytes(8, byteorder='big')
        partial_chunk = full_chunk[:remaining_bytes]
        key_chunks.append(partial_chunk)
    
    # Generate message chunks (8 bytes each)
    message_chunks = []
    full_msg_chunks = message_size_bytes // 8
    remaining_msg_bytes = message_size_bytes % 8
    
    # Full 8-byte chunks
    for i in range(full_msg_chunks):
        chunk_value = message_base + i
        chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
        message_chunks.append(chunk_bytes)
    
    # Partial chunk if needed
    if remaining_msg_bytes > 0:
        chunk_value = message_base + full_msg_chunks
        # Take only the needed bytes from the 8-byte chunk
        full_chunk = chunk_value.to_bytes(8, byteorder='big')
        partial_chunk = full_chunk[:remaining_msg_bytes]
        message_chunks.append(partial_chunk)
    
    # Concatenate to form actual key and message
    key = b''.join(key_chunks)
    message = b''.join(message_chunks)
    
    print(f"\n--- Generated Test Data ---")
    print(f"Key ({len(key)} bytes):")
    for i, chunk in enumerate(key_chunks):
        if i < full_chunks:
            chunk_value = key_base + i
            print(f"  key_chunk[{i}] = {chunk.hex()} (64'h{chunk_value:016x})")
        else:
            # Partial chunk
            print(f"  key_chunk[{i}] = {chunk.hex()} ({len(chunk)} bytes)")
    
    print(f"\nMessage ({len(message)} bytes):")
    for i, chunk in enumerate(message_chunks):
        if i < full_msg_chunks:
            chunk_value = message_base + i
            print(f"  msg_chunk[{i}] = {chunk.hex()} (64'h{chunk_value:016x})")
        else:
            # Partial chunk
            print(f"  msg_chunk[{i}] = {chunk.hex()} ({len(chunk)} bytes)")
    
    print(f"\nConcatenated key: {key.hex()}")
    print(f"Concatenated message: {message.hex()}")
    
    # Compute HMAC-ASCON
    print(f"\n--- Computing HMAC-ASCON ---")
    hmac_tag = hmac_ascon(key, message, "Ascon-Hash256", 32)
    
    print(f"\nHMAC-ASCON result: {hmac_tag.hex()}")
    print(f"Lower 128 bits: {hmac_tag[:16].hex()}")
    print(f"Upper 128 bits: {hmac_tag[16:].hex()}")
    
    return key, message, hmac_tag, key_chunks, message_chunks


def generate_aead_testbench_cases():
    """
    Generate AEAD test cases that match the testbench data exactly.
    This creates the expected results for hardware verification.
    """
    print("=" * 80)
    print("GENERATING AEAD TESTBENCH VERIFICATION DATA")
    print("=" * 80)
    
    # Test 1: Basic AEAD Encryption - matches testbench Test 1
    print("\n--- Test 1: Basic AEAD Encryption ---")
    key_hex = "0f0e0d0c0b0a09080706050403020100"
    nonce_hex = "1f1e1d1c1b1a19181716151413121110"
    ad_hex = "4144"  # "AD" in ASCII
    pt_hex = "5054"  # "PT" in ASCII
    
    # Convert to bytes
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ad = bytes.fromhex(ad_hex)
    plaintext = bytes.fromhex(pt_hex)
    
    print(f"Key:       0x{key_hex}")
    print(f"Nonce:     0x{nonce_hex}")
    print(f"AD:        0x{ad_hex} (\"{ad.decode()}\")")
    print(f"Plaintext: 0x{pt_hex} (\"{plaintext.decode()}\")")
    
    # Perform encryption
    ciphertext, tag = ascon_encrypt(key, nonce, ad, plaintext)
    
    print(f"Ciphertext: 0x{ciphertext.hex()}")
    print(f"Tag:        0x{tag.hex()}")
    
    # Generate Verilog hex constants for hardware
    print(f"\n// Verilog testbench expected values:")
    print(f"// Expected ciphertext (padded to 128-bit)")
    ct_padded = ciphertext + b'\x00' * (16 - len(ciphertext)) if len(ciphertext) < 16 else ciphertext[:16]
    print(f"expected_ciphertext = 128'h{ct_padded.hex()};")
    print(f"// Expected authentication tag")
    print(f"expected_tag = 128'h{tag.hex()};")
    
    # Verify decryption works
    print(f"\n--- Verification (Test 2): Basic AEAD Decryption ---")
    try:
        decrypted = ascon_decrypt(key, nonce, ad, ciphertext + tag)
        if decrypted == plaintext:
            print(f"✓ DECRYPTION VERIFICATION PASSED")
            print(f"Decrypted: 0x{decrypted.hex()} (\"{decrypted.decode()}\")")
        else:
            print(f"✗ DECRYPTION VERIFICATION FAILED")
            print(f"Expected:  0x{plaintext.hex()}")
            print(f"Got:       0x{decrypted.hex()}")
    except Exception as e:
        print(f"✗ DECRYPTION ERROR: {e}")
        
    # Test with partial blocks (5 byte AD, 7 byte PT)
    print(f"\n--- Test 3: Partial Block AEAD ---")
    ad3 = b"HELLO"  # 5 bytes
    pt3 = b"MESSAGE"  # 7 bytes
    key3 = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    nonce3 = bytes.fromhex("2f2e2d2c2b2a29282726252423222120")
    
    print(f"AD:        0x{ad3.hex()} (\"{ad3.decode()}\")")
    print(f"Plaintext: 0x{pt3.hex()} (\"{pt3.decode()}\")")
    
    ciphertext3, tag3 = ascon_encrypt(key3, nonce3, ad3, pt3)
    print(f"Ciphertext: 0x{ciphertext3.hex()}")
    print(f"Tag:        0x{tag3.hex()}")
    
    # Generate Verilog for Test 3
    ct3_padded = ciphertext3 + b'\x00' * (16 - len(ciphertext3)) if len(ciphertext3) < 16 else ciphertext3[:16]
    print(f"// Test 3 Verilog:")
    print(f"expected_ciphertext = 128'h{ct3_padded.hex()};")
    print(f"expected_tag = 128'h{tag3.hex()};")
    
    # Test with full blocks (16 byte each)
    print(f"\n--- Test 4: Full Block AEAD ---")
    ad4 = b"FULLBLOCKADTEST!"  # Exactly 16 bytes
    pt4 = b"FULLBLOCKPTTEST!"  # Exactly 16 bytes
    key4 = bytes.fromhex("1f1e1d1c1b1a19181716151413121110")
    nonce4 = bytes.fromhex("3f3e3d3c3b3a39383736353433323130")
    
    print(f"AD:        0x{ad4.hex()} (\"{ad4.decode()}\")")
    print(f"Plaintext: 0x{pt4.hex()} (\"{pt4.decode()}\")")
    
    ciphertext4, tag4 = ascon_encrypt(key4, nonce4, ad4, pt4)
    print(f"Ciphertext: 0x{ciphertext4.hex()}")
    print(f"Tag:        0x{tag4.hex()}")
    
    print(f"// Test 4 Verilog:")
    print(f"expected_ciphertext = 128'h{ciphertext4.hex()};")
    print(f"expected_tag = 128'h{tag4.hex()};")
    
    # Test with multi-block (20 byte AD, 24 byte PT)
    print(f"\n--- Test 5: Multi-block AEAD ---")
    ad5 = b"MULTIBLOCKADHERETEST"  # 20 bytes
    pt5 = b"MULTIBLOCKPLAINTEXTHERE"  # 24 bytes  
    key5 = bytes.fromhex("2f2e2d2c2b2a29282726252423222120")
    nonce5 = bytes.fromhex("4f4e4d4c4b4a49484746454443424140")
    
    print(f"AD:        0x{ad5.hex()} (\"{ad5.decode()}\")")
    print(f"Plaintext: 0x{pt5.hex()} (\"{pt5.decode()}\")")
    
    ciphertext5, tag5 = ascon_encrypt(key5, nonce5, ad5, pt5)
    print(f"Ciphertext: 0x{ciphertext5.hex()}")
    print(f"Tag:        0x{tag5.hex()}")
    
    # Generate multi-block Verilog
    print(f"// Test 5 Verilog (multi-block):")
    for i in range(0, len(ciphertext5), 16):
        block = ciphertext5[i:i+16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        print(f"expected_ciphertext[{i//16}] = 128'h{block.hex()};")
    print(f"expected_tag = 128'h{tag5.hex()};")
    
    print(f"\n" + "=" * 80)
    print("ALL AEAD TEST CASES GENERATED SUCCESSFULLY")
    print("Copy the expected values to your testbench for verification!")
    print("=" * 80)
    
    return {
        'test1': {'ciphertext': ciphertext.hex(), 'tag': tag.hex()},
        'test3': {'ciphertext': ciphertext3.hex(), 'tag': tag3.hex()},
        'test4': {'ciphertext': ciphertext4.hex(), 'tag': tag4.hex()},
        'test5': {'ciphertext': ciphertext5.hex(), 'tag': tag5.hex()}
    }


def test_exact_testbench_case5():
    """
    Replicate the exact Test 5 from the testbench to debug the hardware issue.
    This uses the EXACT same data as the Verilog testbench.
    """
    print("=" * 80)
    print("REPLICATING EXACT TESTBENCH TEST 5")
    print("=" * 80)
    
    # Exact values from testbench
    key_hex = "2f2e2d2c2b2a29282726252423222120"
    nonce_hex = "4f4e4d4c4b4a49484746454443424140"
    
    print(f"Key:   0x{key_hex}")
    print(f"Nonce: 0x{nonce_hex}")
    
    # Convert to bytes
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    
    # Associated data - exactly as in testbench (with the padding issue!)
    # Block 0: "MULTIBLOCKADHER" = 15 bytes (MISSING 1 padding byte in testbench!)
    ad_block0_hex = "4d554c5449424c4f434b4144484552"  # This is only 15 bytes!
    # Block 1: "ETEST" + padding = 5 + 11 = 16 bytes  
    ad_block1_hex = "45544553540000000000000000000000"
    
    print(f"\n=== ASSOCIATED DATA (testbench format) ===")
    print(f"Block 0: 0x{ad_block0_hex} ({len(ad_block0_hex)//2} bytes)")
    print(f"Block 1: 0x{ad_block1_hex} ({len(ad_block1_hex)//2} bytes)")
    
    # Reconstruct the actual AD data from blocks
    ad_part1 = bytes.fromhex(ad_block0_hex)  # "MULTIBLOCKADHER" (15 bytes)
    ad_part2 = bytes.fromhex(ad_block1_hex)[:5]  # "ETEST" (5 bytes, ignore padding)
    associated_data = ad_part1 + ad_part2  # Total: 20 bytes
    
    print(f"Reconstructed AD: '{associated_data.decode()}' ({len(associated_data)} bytes)")
    print(f"AD hex: 0x{associated_data.hex()}")
    
    # Plaintext data - exactly as in testbench  
    # Block 0: "MULTIBLOCKPLAIN" = 15 bytes (MISSING 1 padding byte in testbench!)
    pt_block0_hex = "4d554c5449424c4f434b504c41494e"  # This is only 15 bytes!
    # Block 1: "TEXTHERE" + padding = 8 + 8 = 16 bytes
    pt_block1_hex = "54455854484552450000000000000000"
    
    print(f"\n=== PLAINTEXT (testbench format) ===")
    print(f"Block 0: 0x{pt_block0_hex} ({len(pt_block0_hex)//2} bytes)")
    print(f"Block 1: 0x{pt_block1_hex} ({len(pt_block1_hex)//2} bytes)")
    
    # Reconstruct the actual PT data from blocks
    pt_part1 = bytes.fromhex(pt_block0_hex)  # "MULTIBLOCKPLAIN" (15 bytes)
    pt_part2 = bytes.fromhex(pt_block1_hex)[:8]  # "TEXTHERE" (8 bytes, ignore padding)
    plaintext = pt_part1 + pt_part2  # Total: 23 bytes
    
    print(f"Reconstructed PT: '{plaintext.decode()}' ({len(plaintext)} bytes)")
    print(f"PT hex: 0x{plaintext.hex()}")
    
    # The testbench comment says "24 bytes" but actual PT is 23 bytes!
    print(f"\n⚠️  TESTBENCH ISSUE: Comment says 24 bytes PT, but actual is {len(plaintext)} bytes!")
    
    # Now perform the ASCON-AEAD encryption with the EXACT data
    print(f"\n=== PERFORMING ASCON-AEAD ENCRYPTION ===")
    
    try:
        ciphertext, tag = ascon_encrypt(key, nonce, associated_data, plaintext)
        
        print(f"✓ ENCRYPTION SUCCESS")
        print(f"Ciphertext: 0x{ciphertext.hex()} ({len(ciphertext)} bytes)")
        print(f"Tag:        0x{tag.hex()}")
        
        # Break ciphertext into 16-byte blocks like hardware expects
        print(f"\n=== EXPECTED HARDWARE OUTPUT ===")
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            if len(block) < 16:
                block_padded = block + b'\x00' * (16 - len(block))
                print(f"Ciphertext[{i//16}] = 128'h{block_padded.hex()}; // {len(block)} bytes + padding")
            else:
                print(f"Ciphertext[{i//16}] = 128'h{block.hex()}; // 16 bytes")
        
        print(f"Tag = 128'h{tag.hex()};")
        
        # Calculate expected parameters for run_aead_test call
        ad_blocks = 2
        ad_last_bytes = 5  # Last 5 bytes in second AD block
        pt_blocks = 2  
        pt_last_bytes = 8  # Last 8 bytes in second PT block (23 total = 15 + 8)
        
        print(f"\n=== TESTBENCH CALL VERIFICATION ===")
        print(f"run_aead_test(1, {ad_blocks}, {ad_last_bytes}, {pt_blocks}, {pt_last_bytes});")
        print(f"// encrypt, {ad_blocks} AD blocks ({len(associated_data)} bytes), {pt_blocks} PT blocks ({len(plaintext)} bytes)")
        
        # Verify decryption
        print(f"\n=== DECRYPTION VERIFICATION ===")
        decrypted = ascon_decrypt(key, nonce, associated_data, ciphertext + tag)
        if decrypted == plaintext:
            print(f"✓ DECRYPTION VERIFICATION PASSED")
        else:
            print(f"✗ DECRYPTION VERIFICATION FAILED")
            print(f"Expected: 0x{plaintext.hex()}")
            print(f"Got:      0x{decrypted.hex()}")
            
        return {
            'key': key_hex,
            'nonce': nonce_hex, 
            'ad': associated_data.hex(),
            'plaintext': plaintext.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex(),
            'ad_blocks': ad_blocks,
            'ad_last_bytes': ad_last_bytes,
            'pt_blocks': pt_blocks,
            'pt_last_bytes': pt_last_bytes
        }
        
    except Exception as e:
        print(f"✗ ENCRYPTION ERROR: {e}")
        return None


def replicate_all_testbench_cases():
    """
    Replicate ALL test cases from the ascon_wrapper_tb.v testbench.
    This generates the expected results for hardware verification.
    """
    print("=" * 80)
    print("REPLICATING ALL TESTBENCH AEAD CASES")
    print("=" * 80)
    
    results = {}
    
    # Test 1: Basic AEAD Encryption with minimal non-empty data
    print("\n--- Test 1: Basic AEAD Encryption ---")
    key1 = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    nonce1 = bytes.fromhex("1f1e1d1c1b1a19181716151413121110")
    ad1 = b"AD"  # 2 bytes
    pt1 = b"PT"  # 2 bytes
    
    print(f"Key: 0x{key1.hex()}")
    print(f"Nonce: 0x{nonce1.hex()}")
    print(f"AD: '{ad1.decode()}' ({len(ad1)} bytes)")
    print(f"PT: '{pt1.decode()}' ({len(pt1)} bytes)")
    
    ct1, tag1 = ascon_encrypt(key1, nonce1, ad1, pt1)
    print(f"Expected ciphertext: 0x{ct1.hex()} ({len(ct1)} bytes)")
    print(f"Expected tag: 0x{tag1.hex()}")
    print(f"Verilog: expected_ciphertext = 128'h{ct1.hex().ljust(32, '0')};")
    print(f"Verilog: expected_tag = 128'h{tag1.hex()};")
    
    results['test1'] = {'key': key1.hex(), 'nonce': nonce1.hex(), 'ad': ad1.hex(), 
                       'pt': pt1.hex(), 'ct': ct1.hex(), 'tag': tag1.hex()}
    
    # Test 2: AEAD Decryption using ciphertext from Test 1
    print("\n--- Test 2: Basic AEAD Decryption ---")
    print("Using ciphertext and tag from Test 1")
    try:
        decrypted1 = ascon_decrypt(key1, nonce1, ad1, ct1 + tag1)
        print(f"Decrypted: '{decrypted1.decode()}' - {'PASS' if decrypted1 == pt1 else 'FAIL'}")
    except Exception as e:
        print(f"Decryption error: {e}")
    
    # Test 3: Partial block AEAD - 5 bytes AD, 7 bytes PT
    print("\n--- Test 3: Partial Block AEAD ---")
    key3 = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    nonce3 = bytes.fromhex("2f2e2d2c2b2a29282726252423222120")
    ad3 = b"HELLO"  # 5 bytes
    pt3 = b"MESSAGE"  # 7 bytes
    
    print(f"AD: '{ad3.decode()}' ({len(ad3)} bytes)")
    print(f"PT: '{pt3.decode()}' ({len(pt3)} bytes)")
    
    ct3, tag3 = ascon_encrypt(key3, nonce3, ad3, pt3)
    print(f"Expected ciphertext: 0x{ct3.hex()} ({len(ct3)} bytes)")
    print(f"Expected tag: 0x{tag3.hex()}")
    print(f"Verilog: expected_ciphertext = 128'h{ct3.hex().ljust(32, '0')};")
    print(f"Verilog: expected_tag = 128'h{tag3.hex()};")
    
    results['test3'] = {'key': key3.hex(), 'nonce': nonce3.hex(), 'ad': ad3.hex(),
                       'pt': pt3.hex(), 'ct': ct3.hex(), 'tag': tag3.hex()}
    
    # Test 4: Full block AEAD - 16 bytes each
    print("\n--- Test 4: Full Block AEAD ---")
    key4 = bytes.fromhex("1f1e1d1c1b1a19181716151413121110")
    nonce4 = bytes.fromhex("3f3e3d3c3b3a39383736353433323130")
    ad4 = b"FULLBLOCKADTEST!"  # 16 bytes exactly
    pt4 = b"FULLBLOCKPTTEST!"  # 16 bytes exactly
    
    print(f"AD: '{ad4.decode()}' ({len(ad4)} bytes)")
    print(f"PT: '{pt4.decode()}' ({len(pt4)} bytes)")
    
    ct4, tag4 = ascon_encrypt(key4, nonce4, ad4, pt4)
    print(f"Expected ciphertext: 0x{ct4.hex()} ({len(ct4)} bytes)")
    print(f"Expected tag: 0x{tag4.hex()}")
    print(f"Verilog: expected_ciphertext = 128'h{ct4.hex()};")
    print(f"Verilog: expected_tag = 128'h{tag4.hex()};")
    
    results['test4'] = {'key': key4.hex(), 'nonce': nonce4.hex(), 'ad': ad4.hex(),
                       'pt': pt4.hex(), 'ct': ct4.hex(), 'tag': tag4.hex()}
    
    # Test 5: Multi-block AEAD - 20 bytes AD, 23 bytes PT (CORRECTED)
    print("\n--- Test 5: Multi-block AEAD (CORRECTED) ---")
    key5 = bytes.fromhex("2f2e2d2c2b2a29282726252423222120")
    nonce5 = bytes.fromhex("4f4e4d4c4b4a49484746454443424140")
    ad5 = b"MULTIBLOCKADHERETEST"  # 20 bytes
    pt5 = b"MULTIBLOCKPLAINTEXTHERE"  # 23 bytes (not 24!)
    
    print(f"AD: '{ad5.decode()}' ({len(ad5)} bytes)")
    print(f"PT: '{pt5.decode()}' ({len(pt5)} bytes)")
    
    ct5, tag5 = ascon_encrypt(key5, nonce5, ad5, pt5)
    print(f"Expected ciphertext: 0x{ct5.hex()} ({len(ct5)} bytes)")
    print(f"Expected tag: 0x{tag5.hex()}")
    
    # Multi-block Verilog format
    print(f"Verilog multi-block format:")
    for i in range(0, len(ct5), 16):
        block = ct5[i:i+16]
        if len(block) < 16:
            block_padded = block + b'\x00' * (16 - len(block))
            print(f"expected_ciphertext[{i//16}] = 128'h{block_padded.hex()}; // {len(block)} bytes + padding")
        else:
            print(f"expected_ciphertext[{i//16}] = 128'h{block.hex()}; // 16 bytes")
    print(f"expected_tag = 128'h{tag5.hex()};")
    
    results['test5'] = {'key': key5.hex(), 'nonce': nonce5.hex(), 'ad': ad5.hex(),
                       'pt': pt5.hex(), 'ct': ct5.hex(), 'tag': tag5.hex()}
    
    # Test 6: Large multi-block AEAD - 35 bytes AD, 40 bytes PT
    print("\n--- Test 6: Large Multi-block AEAD ---")
    key6 = bytes.fromhex("3f3e3d3c3b3a39383736353433323130")
    nonce6 = bytes.fromhex("5f5e5d5c5b5a59585756555453525150")
    
    # Reconstruct from testbench hex (fixing any issues)
    # From testbench: "LARGEMULTIBLOCKAUTHENTICATEDDATA123" (35 bytes)
    ad6 = b"LARGEMULTIBLOCKAUTHENTICATEDDATA123"  # 35 bytes
    # From testbench: "LARGEMULTIBLOCKPLAINTEXTFORMOREADVANCED" (40 bytes)  
    pt6 = b"LARGEMULTIBLOCKPLAINTEXTFORMOREADVANCED"  # 40 bytes
    
    print(f"AD: '{ad6.decode()}' ({len(ad6)} bytes)")
    print(f"PT: '{pt6.decode()}' ({len(pt6)} bytes)")
    
    ct6, tag6 = ascon_encrypt(key6, nonce6, ad6, pt6)
    print(f"Expected ciphertext: 0x{ct6.hex()} ({len(ct6)} bytes)")
    print(f"Expected tag: 0x{tag6.hex()}")
    
    print(f"Verilog multi-block format:")
    for i in range(0, len(ct6), 16):
        block = ct6[i:i+16]
        if len(block) < 16:
            block_padded = block + b'\x00' * (16 - len(block))
            print(f"expected_ciphertext[{i//16}] = 128'h{block_padded.hex()}; // {len(block)} bytes + padding")
        else:
            print(f"expected_ciphertext[{i//16}] = 128'h{block.hex()}; // 16 bytes")
    print(f"expected_tag = 128'h{tag6.hex()};")
    
    results['test6'] = {'key': key6.hex(), 'nonce': nonce6.hex(), 'ad': ad6.hex(),
                       'pt': pt6.hex(), 'ct': ct6.hex(), 'tag': tag6.hex()}
    
    # Test 7: Boundary test - 15 bytes AD, 15 bytes PT
    print("\n--- Test 7: Boundary Test (15 bytes each) ---")
    key7 = bytes.fromhex("4f4e4d4c4b4a49484746454443424140")
    nonce7 = bytes.fromhex("6f6e6d6c6b6a69686766656463626160")
    ad7 = b"FIFTEENBYTESAD!"  # 15 bytes
    pt7 = b"FIFTEENBYTESPT!"  # 15 bytes
    
    print(f"AD: '{ad7.decode()}' ({len(ad7)} bytes)")
    print(f"PT: '{pt7.decode()}' ({len(pt7)} bytes)")
    
    ct7, tag7 = ascon_encrypt(key7, nonce7, ad7, pt7)
    print(f"Expected ciphertext: 0x{ct7.hex()} ({len(ct7)} bytes)")
    print(f"Expected tag: 0x{tag7.hex()}")
    print(f"Verilog: expected_ciphertext = 128'h{ct7.hex().ljust(32, '0')};")
    print(f"Verilog: expected_tag = 128'h{tag7.hex()};")
    
    results['test7'] = {'key': key7.hex(), 'nonce': nonce7.hex(), 'ad': ad7.hex(),
                       'pt': pt7.hex(), 'ct': ct7.hex(), 'tag': tag7.hex()}
    
    # Test 8: Mixed sizes - 3 bytes AD, 25 bytes PT
    print("\n--- Test 8: Mixed Sizes (3-byte AD, 25-byte PT) ---")
    key8 = bytes.fromhex("5f5e5d5c5b5a59585756555453525150")
    nonce8 = bytes.fromhex("7f7e7d7c7b7a79787776757473727170")
    ad8 = b"MIX"  # 3 bytes
    pt8 = b"MIXEDSIZETESTPLAINTEXTABC"  # 25 bytes
    
    print(f"AD: '{ad8.decode()}' ({len(ad8)} bytes)")
    print(f"PT: '{pt8.decode()}' ({len(pt8)} bytes)")
    
    ct8, tag8 = ascon_encrypt(key8, nonce8, ad8, pt8)
    print(f"Expected ciphertext: 0x{ct8.hex()} ({len(ct8)} bytes)")
    print(f"Expected tag: 0x{tag8.hex()}")
    
    print(f"Verilog multi-block format:")
    for i in range(0, len(ct8), 16):
        block = ct8[i:i+16]
        if len(block) < 16:
            block_padded = block + b'\x00' * (16 - len(block))
            print(f"expected_ciphertext[{i//16}] = 128'h{block_padded.hex()}; // {len(block)} bytes + padding")
        else:
            print(f"expected_ciphertext[{i//16}] = 128'h{block.hex()}; // 16 bytes")
    print(f"expected_tag = 128'h{tag8.hex()};")
    
    results['test8'] = {'key': key8.hex(), 'nonce': nonce8.hex(), 'ad': ad8.hex(),
                       'pt': pt8.hex(), 'ct': ct8.hex(), 'tag': tag8.hex()}
    
    # Test 9: Round-trip encrypt-decrypt test
    print("\n--- Test 9: Round-trip Encrypt-Decrypt Test ---")
    key9 = bytes.fromhex("6f6e6d6c6b6a69686766656463626160")
    nonce9 = bytes.fromhex("8f8e8d8c8b8a89888786858483828180")
    ad9 = b"ROUNDTRIP"  # 9 bytes
    pt9 = b"ENCRYPT_DECRYPT_TEST"  # 20 bytes
    
    print(f"AD: '{ad9.decode()}' ({len(ad9)} bytes)")
    print(f"PT: '{pt9.decode()}' ({len(pt9)} bytes)")
    
    ct9, tag9 = ascon_encrypt(key9, nonce9, ad9, pt9)
    print(f"Expected ciphertext: 0x{ct9.hex()} ({len(ct9)} bytes)")
    print(f"Expected tag: 0x{tag9.hex()}")
    
    print(f"Verilog multi-block format:")
    for i in range(0, len(ct9), 16):
        block = ct9[i:i+16]
        if len(block) < 16:
            block_padded = block + b'\x00' * (16 - len(block))
            print(f"expected_ciphertext[{i//16}] = 128'h{block_padded.hex()}; // {len(block)} bytes + padding")
        else:
            print(f"expected_ciphertext[{i//16}] = 128'h{block.hex()}; // 16 bytes")
    print(f"expected_tag = 128'h{tag9.hex()};")
    
    # Verify round-trip
    try:
        decrypted9 = ascon_decrypt(key9, nonce9, ad9, ct9 + tag9)
        print(f"Round-trip verification: {'PASS' if decrypted9 == pt9 else 'FAIL'}")
    except Exception as e:
        print(f"Round-trip error: {e}")
    
    results['test9'] = {'key': key9.hex(), 'nonce': nonce9.hex(), 'ad': ad9.hex(),
                       'pt': pt9.hex(), 'ct': ct9.hex(), 'tag': tag9.hex()}
    
    # Test 10: Different key/nonce combination with compact data
    print("\n--- Test 10: Different Key/Nonce Test ---")
    key10 = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    nonce10 = bytes.fromhex("123456789abcdef0fedcba9876543210")
    ad10 = b"DIFFERENT"  # 9 bytes
    pt10 = b"KEYNONCETEST"  # 12 bytes
    
    print(f"AD: '{ad10.decode()}' ({len(ad10)} bytes)")
    print(f"PT: '{pt10.decode()}' ({len(pt10)} bytes)")
    
    ct10, tag10 = ascon_encrypt(key10, nonce10, ad10, pt10)
    print(f"Expected ciphertext: 0x{ct10.hex()} ({len(ct10)} bytes)")
    print(f"Expected tag: 0x{tag10.hex()}")
    print(f"Verilog: expected_ciphertext = 128'h{ct10.hex().ljust(32, '0')};")
    print(f"Verilog: expected_tag = 128'h{tag10.hex()};")
    
    results['test10'] = {'key': key10.hex(), 'nonce': nonce10.hex(), 'ad': ad10.hex(),
                        'pt': pt10.hex(), 'ct': ct10.hex(), 'tag': tag10.hex()}
    
    print("\n" + "=" * 80)
    print("ALL TESTBENCH AEAD CASES REPLICATED SUCCESSFULLY")
    print("Copy the expected values to your testbench for verification!")
    print("=" * 80)
    
    return results


def generate_verilog_testbench_patterns():
    """
    Generate Verilog patterns in the exact format used in the testbench,
    with proper block breakdown and hex formatting.
    """
    print("=" * 80)
    print("EXACT VERILOG TESTBENCH PATTERNS")
    print("=" * 80)
    
    def string_to_hex_blocks(s, block_size=16):
        """Convert string or bytes to hex blocks with proper formatting"""
        if isinstance(s, str):
            data = s.encode('utf-8')
        else:
            data = s  # Already bytes
        blocks = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) < block_size:
                block = block + b'\x00' * (block_size - len(block))
            hex_str = ''.join([f'{b:02x}' for b in block])
            # Add underscores every 4 characters for readability
            formatted_hex = '_'.join([hex_str[j:j+4] for j in range(0, len(hex_str), 4)])
            blocks.append((formatted_hex.upper(), block))
        return blocks
    
    def calculate_blocks_and_remainder(data_bytes):
        """Calculate number of blocks and remainder bytes"""
        total_bytes = len(data_bytes)
        full_blocks = total_bytes // 16
        remainder = total_bytes % 16
        total_blocks = full_blocks + (1 if remainder > 0 else 0)
        return total_blocks, remainder if remainder > 0 else (16 if full_blocks > 0 else 0)
    
    # # Test 1: Basic AEAD Encryption
    # print("\n// ========================================")
    # print("// Test 1: Basic AEAD Encryption")
    # print("// ========================================")
    # key1 = "0f0e0d0c0b0a09080706050403020100"
    # nonce1 = "1f1e1d1c1b1a19181716151413121110"
    # ad1 = "AD"
    # pt1 = "PT"
    
    # print(f"aead_key_in = 128'h{key1};")
    # print(f"aead_nonce_in = 128'h{nonce1};")
    # print(f"")
    # print(f'// Associated data: "{ad1}" ({len(ad1)} bytes)')
    # ad1_blocks = string_to_hex_blocks(ad1)
    # for i, (hex_block, orig_bytes) in enumerate(ad1_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt1}" ({len(pt1)} bytes)')
    # pt1_blocks = string_to_hex_blocks(pt1)
    # for i, (hex_block, orig_bytes) in enumerate(pt1_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad1_total_blocks, ad1_remainder = calculate_blocks_and_remainder(ad1.encode())
    # pt1_total_blocks, pt1_remainder = calculate_blocks_and_remainder(pt1.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad1_total_blocks}, {ad1_remainder}, {pt1_total_blocks}, {pt1_remainder}); // encrypt")
    
    # # Get expected results
    # key1_bytes = bytes.fromhex(key1)
    # nonce1_bytes = bytes.fromhex(nonce1)
    # ad1_bytes = ad1.encode()
    # pt1_bytes = pt1.encode()
    # ct1, tag1 = ascon_encrypt(key1_bytes, nonce1_bytes, ad1_bytes, pt1_bytes)
    # print(f"// Expected ciphertext: {ct1.hex()}")
    # print(f"// Expected tag: {tag1.hex()}")
    
    # # Test 5: Multi-block AEAD (CORRECTED)
    # print("\n// ========================================")
    # print("// Test 5: Multi-block AEAD (CORRECTED)")
    # print("// ========================================")
    # key5 = "2f2e2d2c2b2a29282726252423222120"
    # nonce5 = "4f4e4d4c4b4a49484746454443424140"
    # ad5 = "MULTIBLOCKADHERETEST"  # 20 bytes
    # pt5 = "MULTIBLOCKPLAINTEXTHERE"  # 23 bytes (not 24!)
    
    # print(f"aead_key_in = 128'h{key5};")
    # print(f"aead_nonce_in = 128'h{nonce5};")
    # print(f"")
    # print(f'// Associated data: "{ad5}" ({len(ad5)} bytes - spans 2 blocks)')
    # ad5_blocks = string_to_hex_blocks(ad5)
    # for i, (hex_block, orig_bytes) in enumerate(ad5_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt5}" ({len(pt5)} bytes - spans 2 blocks) - CORRECTED!')
    # pt5_blocks = string_to_hex_blocks(pt5)
    # for i, (hex_block, orig_bytes) in enumerate(pt5_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad5_total_blocks, ad5_remainder = calculate_blocks_and_remainder(ad5.encode())
    # pt5_total_blocks, pt5_remainder = calculate_blocks_and_remainder(pt5.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad5_total_blocks}, {ad5_remainder}, {pt5_total_blocks}, {pt5_remainder}); // encrypt, CORRECTED: last_bytes = {pt5_remainder}")
    
    # # Get expected results
    # key5_bytes = bytes.fromhex(key5)
    # nonce5_bytes = bytes.fromhex(nonce5)
    # ad5_bytes = ad5.encode()
    # pt5_bytes = pt5.encode()
    # ct5, tag5 = ascon_encrypt(key5_bytes, nonce5_bytes, ad5_bytes, pt5_bytes)
    # print(f"// Expected ciphertext: {ct5.hex()}")
    # print(f"// Expected tag: {tag5.hex()}")

    # ct5_decrypted = ascon_decrypt(key5_bytes, nonce5_bytes, ad5_bytes, ct5 + tag5)
    # if ct5_decrypted == pt5_bytes:
    #     print(f"// Decryption verification: PASS")
    # else:
    #     print(f"// Decryption verification: FAIL - got {ct5_decrypted.hex()} expected {pt5_bytes.hex()}")



    
    # # Test 6: Large Multi-block AEAD (CORRECTED)
    # print("\n// ========================================")
    # print("// Test 6: Large Multi-block AEAD (CORRECTED)")
    # print("// ========================================")
    # key6 = "3f3e3d3c3b3a39383736353433323130"
    # nonce6 = "5f5e5d5c5b5a59585756555453525150"
    # ad6 = "LARGEMULTIBLOCKAUTHENTICATEDDATA123"  # 35 bytes
    # pt6 = "LARGEMULTIBLOCKPLAINTEXTFORMOREADVANCED"  # 39 bytes (not 40!)
    
    # print(f"aead_key_in = 128'h{key6};")
    # print(f"aead_nonce_in = 128'h{nonce6};")
    # print(f"")
    # print(f'// Associated data: "{ad6}" ({len(ad6)} bytes - spans 3 blocks)')
    # ad6_blocks = string_to_hex_blocks(ad6)
    # for i, (hex_block, orig_bytes) in enumerate(ad6_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt6}" ({len(pt6)} bytes - spans 3 blocks) - CORRECTED!')
    # pt6_blocks = string_to_hex_blocks(pt6)
    # for i, (hex_block, orig_bytes) in enumerate(pt6_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad6_total_blocks, ad6_remainder = calculate_blocks_and_remainder(ad6.encode())
    # pt6_total_blocks, pt6_remainder = calculate_blocks_and_remainder(pt6.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad6_total_blocks}, {ad6_remainder}, {pt6_total_blocks}, {pt6_remainder}); // encrypt, CORRECTED: last_bytes = {pt6_remainder}")
    
    # # Get expected results
    # key6_bytes = bytes.fromhex(key6)
    # nonce6_bytes = bytes.fromhex(nonce6)
    # ad6_bytes = ad6.encode()
    # pt6_bytes = pt6.encode()
    # ct6, tag6 = ascon_encrypt(key6_bytes, nonce6_bytes, ad6_bytes, pt6_bytes)
    # print(f"// Expected ciphertext: {ct6.hex()}")
    # print(f"// Expected tag: {tag6.hex()}")
    

    # print(f"")
    # print(f'// Ciphertext: "{ct6.hex()}" ({len(ct6)} bytes - spans 3 blocks) - CORRECTED!')
    # ct6_blocks = string_to_hex_blocks(ct6)
    # for i, (hex_block, orig_bytes) in enumerate(ct6_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")


    # ct6_decrypted = ascon_decrypt(key6_bytes, nonce6_bytes, ad6_bytes, ct6 + tag6)
    # if ct6_decrypted == pt6_bytes:
    #     print(f"// Decryption verification: PASS")
    # else:
    #     print(f"// Decryption verification: FAIL - got {ct6_decrypted.hex()} expected {pt6_bytes.hex()}")


    # Test 4: Full Block AEAD
    print("\n// ========================================")
    print("// Test 4: Full Block AEAD")
    print("// ========================================")
    key4 = "1f1e1d1c1b1a19181716151413121110"
    nonce4 = "3f3e3d3c3b3a39383736353433323130"
    ad4 = "FULLBLOCKADTEST!"  # 16 bytes
    pt4 = "FULLBLOCKPTTEST!"  # 16 bytes
    
    print(f"aead_key_in = 128'h{key4};")
    print(f"aead_nonce_in = 128'h{nonce4};")
    print(f"")
    print(f'// Associated data: "{ad4}" ({len(ad4)} bytes - exactly 1 block)')
    ad4_blocks = string_to_hex_blocks(ad4)
    for i, (hex_block, orig_bytes) in enumerate(ad4_blocks):
        content = orig_bytes.decode('utf-8')
        print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    print(f"")
    print(f'// Plaintext: "{pt4}" ({len(pt4)} bytes - exactly 1 block)')
    pt4_blocks = string_to_hex_blocks(pt4)
    for i, (hex_block, orig_bytes) in enumerate(pt4_blocks):
        content = orig_bytes.decode('utf-8')
        print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    print(f"")
    print(f"run_aead_test(1, 1, 0, 1, 0); // encrypt, full blocks only")
    
    # Get expected results
    key4_bytes = bytes.fromhex(key4)
    nonce4_bytes = bytes.fromhex(nonce4)
    ad4_bytes = ad4.encode()
    pt4_bytes = pt4.encode()
    ct4, tag4 = ascon_encrypt(key4_bytes, nonce4_bytes, ad4_bytes, pt4_bytes)
    print(f"// Expected ciphertext: {ct4.hex()}")
    print(f"// Expected tag: {tag4.hex()}")
    

    print(f"")
    print(f'// Ciphertext: "{ct4.hex()}" ({len(ct4)} bytes - spans 1 block) - CORRECTED!')
    ct4_blocks = string_to_hex_blocks(ct4)
    for i, (hex_block, orig_bytes) in enumerate(ct4_blocks):
        content = orig_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
        padding = " + zeros" if b'\x00' in orig_bytes else ""
        print(f"ciphertext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")


    ct4_decrypted = ascon_decrypt(key4_bytes, nonce4_bytes, ad4_bytes, ct4 + tag4)
    if ct4_decrypted == pt4_bytes:
        print(f"// Decryption verification: PASS")
    else:
        print(f"// Decryption verification: FAIL - got {ct4_decrypted.hex()} expected {pt4_bytes.hex()}")

    # # Test 7: 15-byte Boundary Cases
    # print("\n// ========================================")
    # print("// Test 7: 15-byte Boundary Cases")
    # print("// ========================================")
    # key7 = "6f6e6d6c6b6a69686766656463626160"
    # nonce7 = "8f8e8d8c8b8a89888786858483828180"
    # ad7 = "FIFTEENBYTESAD!"  # 15 bytes - boundary case
    # pt7 = "FIFTEENBYTESPT!"  # 15 bytes - boundary case
    
    # print(f"aead_key_in = 128'h{key7};")
    # print(f"aead_nonce_in = 128'h{nonce7};")
    # print(f"")
    # print(f'// Associated data: "{ad7}" ({len(ad7)} bytes - boundary case)')
    # ad7_blocks = string_to_hex_blocks(ad7)
    # for i, (hex_block, orig_bytes) in enumerate(ad7_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt7}" ({len(pt7)} bytes - boundary case)')
    # pt7_blocks = string_to_hex_blocks(pt7)
    # for i, (hex_block, orig_bytes) in enumerate(pt7_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad7_total_blocks, ad7_remainder = calculate_blocks_and_remainder(ad7.encode())
    # pt7_total_blocks, pt7_remainder = calculate_blocks_and_remainder(pt7.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad7_total_blocks}, {ad7_remainder}, {pt7_total_blocks}, {pt7_remainder}); // encrypt, boundary case")
    
    # # Get expected results
    # key7_bytes = bytes.fromhex(key7)
    # nonce7_bytes = bytes.fromhex(nonce7)
    # ad7_bytes = ad7.encode()
    # pt7_bytes = pt7.encode()
    # ct7, tag7 = ascon_encrypt(key7_bytes, nonce7_bytes, ad7_bytes, pt7_bytes)
    # print(f"// Expected ciphertext: {ct7.hex()}")
    # print(f"// Expected tag: {tag7.hex()}")
    
    # # Test 8: Mixed Size Multi-block
    # print("\n// ========================================")
    # print("// Test 8: Mixed Size Multi-block")
    # print("// ========================================")
    # key8 = "7f7e7d7c7b7a79787776757473727170"
    # nonce8 = "9f9e9d9c9b9a99989796959493929190"
    # ad8 = "SHORT"  # 5 bytes
    # pt8 = "LONGERPLAINTEXTMULTIBLOCKTEST"  # 29 bytes - spans 2 blocks
    
    # print(f"aead_key_in = 128'h{key8};")
    # print(f"aead_nonce_in = 128'h{nonce8};")
    # print(f"")
    # print(f'// Associated data: "{ad8}" ({len(ad8)} bytes)')
    # ad8_blocks = string_to_hex_blocks(ad8)
    # for i, (hex_block, orig_bytes) in enumerate(ad8_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt8}" ({len(pt8)} bytes - spans 2 blocks)')
    # pt8_blocks = string_to_hex_blocks(pt8)
    # for i, (hex_block, orig_bytes) in enumerate(pt8_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad8_total_blocks, ad8_remainder = calculate_blocks_and_remainder(ad8.encode())
    # pt8_total_blocks, pt8_remainder = calculate_blocks_and_remainder(pt8.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad8_total_blocks}, {ad8_remainder}, {pt8_total_blocks}, {pt8_remainder}); // encrypt, mixed sizes")
    
    # # Get expected results
    # key8_bytes = bytes.fromhex(key8)
    # nonce8_bytes = bytes.fromhex(nonce8)
    # ad8_bytes = ad8.encode()
    # pt8_bytes = pt8.encode()
    # ct8, tag8 = ascon_encrypt(key8_bytes, nonce8_bytes, ad8_bytes, pt8_bytes)
    # print(f"// Expected ciphertext: {ct8.hex()}")
    # print(f"// Expected tag: {tag8.hex()}")
    
    # # Test 9: Single Byte Data
    # print("\n// ========================================")
    # print("// Test 9: Single Byte Data")
    # print("// ========================================")
    # key9 = "8f8e8d8c8b8a89888786858483828180"
    # nonce9 = "afaeadacabaaa9a8a7a6a5a4a3a2a1a0"
    # ad9 = "A"  # 1 byte
    # pt9 = "B"  # 1 byte
    
    # print(f"aead_key_in = 128'h{key9};")
    # print(f"aead_nonce_in = 128'h{nonce9};")
    # print(f"")
    # print(f'// Associated data: "{ad9}" ({len(ad9)} byte)')
    # ad9_blocks = string_to_hex_blocks(ad9)
    # for i, (hex_block, orig_bytes) in enumerate(ad9_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt9}" ({len(pt9)} byte)')
    # pt9_blocks = string_to_hex_blocks(pt9)
    # for i, (hex_block, orig_bytes) in enumerate(pt9_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad9_total_blocks, ad9_remainder = calculate_blocks_and_remainder(ad9.encode())
    # pt9_total_blocks, pt9_remainder = calculate_blocks_and_remainder(pt9.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad9_total_blocks}, {ad9_remainder}, {pt9_total_blocks}, {pt9_remainder}); // encrypt, minimal data")
    
    # # Get expected results
    # key9_bytes = bytes.fromhex(key9)
    # nonce9_bytes = bytes.fromhex(nonce9)
    # ad9_bytes = ad9.encode()
    # pt9_bytes = pt9.encode()
    # ct9, tag9 = ascon_encrypt(key9_bytes, nonce9_bytes, ad9_bytes, pt9_bytes)
    # print(f"// Expected ciphertext: {ct9.hex()}")
    # print(f"// Expected tag: {tag9.hex()}")
    
    # # Test 10: Maximum 3-block Test
    # print("\n// ========================================")
    # print("// Test 10: Maximum 3-block Test")
    # print("// ========================================")
    # key10 = "9f9e9d9c9b9a99989796959493929190"
    # nonce10 = "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0"
    # ad10 = "MAXIMUMTHREEBLOCKASSOCIATEDDATAFORTES"  # 37 bytes - spans 3 blocks
    # pt10 = "MAXIMUMTHREEBLOCKPLAINTEXTDATAFORTESTING"  # 40 bytes - spans 3 blocks
    
    # print(f"aead_key_in = 128'h{key10};")
    # print(f"aead_nonce_in = 128'h{nonce10};")
    # print(f"")
    # print(f'// Associated data: "{ad10}" ({len(ad10)} bytes - spans 3 blocks)')
    # ad10_blocks = string_to_hex_blocks(ad10)
    # for i, (hex_block, orig_bytes) in enumerate(ad10_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Plaintext: "{pt10}" ({len(pt10)} bytes - spans 3 blocks)')
    # pt10_blocks = string_to_hex_blocks(pt10)
    # for i, (hex_block, orig_bytes) in enumerate(pt10_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"plaintext_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # ad10_total_blocks, ad10_remainder = calculate_blocks_and_remainder(ad10.encode())
    # pt10_total_blocks, pt10_remainder = calculate_blocks_and_remainder(pt10.encode())
    # print(f"")
    # print(f"run_aead_test(1, {ad10_total_blocks}, {ad10_remainder}, {pt10_total_blocks}, {pt10_remainder}); // encrypt, max 3-block")
    
    # # Get expected results
    # key10_bytes = bytes.fromhex(key10)
    # nonce10_bytes = bytes.fromhex(nonce10)
    # ad10_bytes = ad10.encode()
    # pt10_bytes = pt10.encode()
    # ct10, tag10 = ascon_encrypt(key10_bytes, nonce10_bytes, ad10_bytes, pt10_bytes)
    # print(f"// Expected ciphertext: {ct10.hex()}")
    # print(f"// Expected tag: {tag10.hex()}")
    
    # print("\n" + "=" * 80)
    # print("DECRYPTION TEST PATTERNS")
    # print("=" * 80)
    
    # # Test 1 Decryption: Basic AEAD
    # print("\n// ========================================")
    # print("// Test 1: Basic AEAD Decryption")
    # print("// ========================================")
    # key1 = "0f0e0d0c0b0a09080706050403020100"
    # nonce1 = "1f1e1d1c1b1a19181716151413121110"
    # ad1 = "AD"
    # pt1 = "PT"
    
    # key1_bytes = bytes.fromhex(key1)
    # nonce1_bytes = bytes.fromhex(nonce1)
    # ad1_bytes = ad1.encode()
    # pt1_bytes = pt1.encode()
    # ct1, tag1 = ascon_encrypt(key1_bytes, nonce1_bytes, ad1_bytes, pt1_bytes)
    
    # print(f"aead_key_in = 128'h{key1};")
    # print(f"aead_nonce_in = 128'h{nonce1};")
    # print(f"")
    # print(f'// Associated data: "{ad1}" ({len(ad1)} bytes)')
    # ad1_blocks = string_to_hex_blocks(ad1)
    # for i, (hex_block, orig_bytes) in enumerate(ad1_blocks):
    #     content = orig_bytes.rstrip(b'\x00').decode('utf-8')
    #     padding = " + zeros" if b'\x00' in orig_bytes else ""
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"{padding}")
    
    # print(f"")
    # print(f'// Ciphertext: {ct1.hex()} ({len(ct1)} bytes)')
    # ct1_blocks = string_to_hex_blocks(ct1)
    # for i, (hex_block, orig_bytes) in enumerate(ct1_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag1.hex()};")
    
    # ad1_total_blocks, ad1_remainder = calculate_blocks_and_remainder(ad1_bytes)
    # ct1_total_blocks, ct1_remainder = calculate_blocks_and_remainder(ct1)
    # print(f"")
    # print(f"run_aead_test(0, {ad1_total_blocks}, {ad1_remainder}, {ct1_total_blocks}, {ct1_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt1}")
    # print(f"// Should return tag_valid = 1")

    # # Test 4 Decryption: Full Block AEAD  
    # print("\n// ========================================")
    # print("// Test 4: Full Block AEAD Decryption")
    # print("// ========================================")
    # key4 = "1f1e1d1c1b1a19181716151413121110"
    # nonce4 = "3f3e3d3c3b3a39383736353433323130"
    # ad4 = "FULLBLOCKADTEST!"
    # pt4 = "FULLBLOCKPTTEST!"
    
    # key4_bytes = bytes.fromhex(key4)
    # nonce4_bytes = bytes.fromhex(nonce4)
    # ad4_bytes = ad4.encode()
    # pt4_bytes = pt4.encode()
    # ct4, tag4 = ascon_encrypt(key4_bytes, nonce4_bytes, ad4_bytes, pt4_bytes)
    
    # print(f"aead_key_in = 128'h{key4};")
    # print(f"aead_nonce_in = 128'h{nonce4};")
    # print(f"")
    # print(f'// Associated data: "{ad4}" ({len(ad4)} bytes)')
    # ad4_blocks = string_to_hex_blocks(ad4)
    # for i, (hex_block, orig_bytes) in enumerate(ad4_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct4.hex()} ({len(ct4)} bytes)')
    # ct4_blocks = string_to_hex_blocks(ct4)
    # for i, (hex_block, orig_bytes) in enumerate(ct4_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag4.hex()};")
    
    # ad4_total_blocks, ad4_remainder = calculate_blocks_and_remainder(ad4_bytes)
    # ct4_total_blocks, ct4_remainder = calculate_blocks_and_remainder(ct4)
    # print(f"")
    # print(f"run_aead_test(0, {ad4_total_blocks}, {ad4_remainder}, {ct4_total_blocks}, {ct4_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt4}")
    # print(f"// Should return tag_valid = 1")

    # # Test 5 Decryption: Multi-block AEAD
    # print("\n// ========================================")
    # print("// Test 5: Multi-block AEAD Decryption")
    # print("// ========================================")
    # key5 = "2f2e2d2c2b2a29282726252423222120"
    # nonce5 = "4f4e4d4c4b4a49484746454443424140"
    # ad5 = "MULTIBLOCKADHERETEST"
    # pt5 = "MULTIBLOCKPLAINTEXTHERE"
    
    # key5_bytes = bytes.fromhex(key5)
    # nonce5_bytes = bytes.fromhex(nonce5)
    # ad5_bytes = ad5.encode()
    # pt5_bytes = pt5.encode()
    # ct5, tag5 = ascon_encrypt(key5_bytes, nonce5_bytes, ad5_bytes, pt5_bytes)
    
    # print(f"aead_key_in = 128'h{key5};")
    # print(f"aead_nonce_in = 128'h{nonce5};")
    # print(f"")
    # print(f'// Associated data: "{ad5}" ({len(ad5)} bytes)')
    # ad5_blocks = string_to_hex_blocks(ad5)
    # for i, (hex_block, orig_bytes) in enumerate(ad5_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct5.hex()} ({len(ct5)} bytes)')
    # ct5_blocks = string_to_hex_blocks(ct5)
    # for i, (hex_block, orig_bytes) in enumerate(ct5_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag5.hex()};")
    
    # ad5_total_blocks, ad5_remainder = calculate_blocks_and_remainder(ad5_bytes)
    # ct5_total_blocks, ct5_remainder = calculate_blocks_and_remainder(ct5)
    # print(f"")
    # print(f"run_aead_test(0, {ad5_total_blocks}, {ad5_remainder}, {ct5_total_blocks}, {ct5_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt5}")
    # print(f"// Should return tag_valid = 1")

    # # Test 6 Decryption: Large Multi-block AEAD
    # print("\n// ========================================")
    # print("// Test 6: Large Multi-block AEAD Decryption")
    # print("// ========================================")
    # key6 = "3f3e3d3c3b3a39383736353433323130"
    # nonce6 = "5f5e5d5c5b5a59585756555453525150"
    # ad6 = "LARGEMULTIBLOCKAUTHENTICATEDDATA123"
    # pt6 = "LARGEMULTIBLOCKPLAINTEXTFORMOREADVANCED"
    
    # key6_bytes = bytes.fromhex(key6)
    # nonce6_bytes = bytes.fromhex(nonce6)
    # ad6_bytes = ad6.encode()
    # pt6_bytes = pt6.encode()
    # ct6, tag6 = ascon_encrypt(key6_bytes, nonce6_bytes, ad6_bytes, pt6_bytes)
    
    # print(f"aead_key_in = 128'h{key6};")
    # print(f"aead_nonce_in = 128'h{nonce6};")
    # print(f"")
    # print(f'// Associated data: "{ad6}" ({len(ad6)} bytes)')
    # ad6_blocks = string_to_hex_blocks(ad6)
    # for i, (hex_block, orig_bytes) in enumerate(ad6_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct6.hex()} ({len(ct6)} bytes)')
    # ct6_blocks = string_to_hex_blocks(ct6)
    # for i, (hex_block, orig_bytes) in enumerate(ct6_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag6.hex()};")
    
    # ad6_total_blocks, ad6_remainder = calculate_blocks_and_remainder(ad6_bytes)
    # ct6_total_blocks, ct6_remainder = calculate_blocks_and_remainder(ct6)
    # print(f"")
    # print(f"run_aead_test(0, {ad6_total_blocks}, {ad6_remainder}, {ct6_total_blocks}, {ct6_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt6}")
    # print(f"// Should return tag_valid = 1")

    # # Test 7 Decryption: 15-byte Boundary Cases
    # print("\n// ========================================")
    # print("// Test 7: 15-byte Boundary Cases Decryption")
    # print("// ========================================")
    # key7 = "6f6e6d6c6b6a69686766656463626160"
    # nonce7 = "8f8e8d8c8b8a89888786858483828180"
    # ad7 = "FIFTEENBYTESAD!"
    # pt7 = "FIFTEENBYTESPT!"
    
    # key7_bytes = bytes.fromhex(key7)
    # nonce7_bytes = bytes.fromhex(nonce7)
    # ad7_bytes = ad7.encode()
    # pt7_bytes = pt7.encode()
    # ct7, tag7 = ascon_encrypt(key7_bytes, nonce7_bytes, ad7_bytes, pt7_bytes)
    
    # print(f"aead_key_in = 128'h{key7};")
    # print(f"aead_nonce_in = 128'h{nonce7};")
    # print(f"")
    # print(f'// Associated data: "{ad7}" ({len(ad7)} bytes)')
    # ad7_blocks = string_to_hex_blocks(ad7)
    # for i, (hex_block, orig_bytes) in enumerate(ad7_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct7.hex()} ({len(ct7)} bytes)')
    # ct7_blocks = string_to_hex_blocks(ct7)
    # for i, (hex_block, orig_bytes) in enumerate(ct7_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag7.hex()};")
    
    # ad7_total_blocks, ad7_remainder = calculate_blocks_and_remainder(ad7_bytes)
    # ct7_total_blocks, ct7_remainder = calculate_blocks_and_remainder(ct7)
    # print(f"")
    # print(f"run_aead_test(0, {ad7_total_blocks}, {ad7_remainder}, {ct7_total_blocks}, {ct7_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt7}")
    # print(f"// Should return tag_valid = 1")

    # # Test 8 Decryption: Mixed Size Multi-block
    # print("\n// ========================================")
    # print("// Test 8: Mixed Size Multi-block Decryption")
    # print("// ========================================")
    # key8 = "7f7e7d7c7b7a79787776757473727170"
    # nonce8 = "9f9e9d9c9b9a99989796959493929190"
    # ad8 = "SHORT"
    # pt8 = "LONGERPLAINTEXTMULTIBLOCKTEST"
    
    # key8_bytes = bytes.fromhex(key8)
    # nonce8_bytes = bytes.fromhex(nonce8)
    # ad8_bytes = ad8.encode()
    # pt8_bytes = pt8.encode()
    # ct8, tag8 = ascon_encrypt(key8_bytes, nonce8_bytes, ad8_bytes, pt8_bytes)
    
    # print(f"aead_key_in = 128'h{key8};")
    # print(f"aead_nonce_in = 128'h{nonce8};")
    # print(f"")
    # print(f'// Associated data: "{ad8}" ({len(ad8)} bytes)')
    # ad8_blocks = string_to_hex_blocks(ad8)
    # for i, (hex_block, orig_bytes) in enumerate(ad8_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct8.hex()} ({len(ct8)} bytes)')
    # ct8_blocks = string_to_hex_blocks(ct8)
    # for i, (hex_block, orig_bytes) in enumerate(ct8_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag8.hex()};")
    
    # ad8_total_blocks, ad8_remainder = calculate_blocks_and_remainder(ad8_bytes)
    # ct8_total_blocks, ct8_remainder = calculate_blocks_and_remainder(ct8)
    # print(f"")
    # print(f"run_aead_test(0, {ad8_total_blocks}, {ad8_remainder}, {ct8_total_blocks}, {ct8_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt8}")
    # print(f"// Should return tag_valid = 1")

    # # Test 9 Decryption: Single Byte Data
    # print("\n// ========================================")
    # print("// Test 9: Single Byte Data Decryption")
    # print("// ========================================")
    # key9 = "8f8e8d8c8b8a89888786858483828180"
    # nonce9 = "afaeadacabaaa9a8a7a6a5a4a3a2a1a0"
    # ad9 = "A"
    # pt9 = "B"
    
    # key9_bytes = bytes.fromhex(key9)
    # nonce9_bytes = bytes.fromhex(nonce9)
    # ad9_bytes = ad9.encode()
    # pt9_bytes = pt9.encode()
    # ct9, tag9 = ascon_encrypt(key9_bytes, nonce9_bytes, ad9_bytes, pt9_bytes)
    
    # print(f"aead_key_in = 128'h{key9};")
    # print(f"aead_nonce_in = 128'h{nonce9};")
    # print(f"")
    # print(f'// Associated data: "{ad9}" ({len(ad9)} bytes)')
    # ad9_blocks = string_to_hex_blocks(ad9)
    # for i, (hex_block, orig_bytes) in enumerate(ad9_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct9.hex()} ({len(ct9)} bytes)')
    # ct9_blocks = string_to_hex_blocks(ct9)
    # for i, (hex_block, orig_bytes) in enumerate(ct9_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag9.hex()};")
    
    # ad9_total_blocks, ad9_remainder = calculate_blocks_and_remainder(ad9_bytes)
    # ct9_total_blocks, ct9_remainder = calculate_blocks_and_remainder(ct9)
    # print(f"")
    # print(f"run_aead_test(0, {ad9_total_blocks}, {ad9_remainder}, {ct9_total_blocks}, {ct9_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt9}")
    # print(f"// Should return tag_valid = 1")

    # # Test 10 Decryption: Maximum 3-block Test
    # print("\n// ========================================")
    # print("// Test 10: Maximum 3-block Test Decryption")
    # print("// ========================================")
    # key10 = "9f9e9d9c9b9a99989796959493929190"
    # nonce10 = "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0"
    # ad10 = "MAXIMUMTHREEBLOCKASSOCIATEDDATAFORTES"
    # pt10 = "MAXIMUMTHREEBLOCKPLAINTEXTDATAFORTESTING"
    
    # key10_bytes = bytes.fromhex(key10)
    # nonce10_bytes = bytes.fromhex(nonce10)
    # ad10_bytes = ad10.encode()
    # pt10_bytes = pt10.encode()
    # ct10, tag10 = ascon_encrypt(key10_bytes, nonce10_bytes, ad10_bytes, pt10_bytes)
    
    # print(f"aead_key_in = 128'h{key10};")
    # print(f"aead_nonce_in = 128'h{nonce10};")
    # print(f"")
    # print(f'// Associated data: "{ad10}" ({len(ad10)} bytes)')
    # ad10_blocks = string_to_hex_blocks(ad10)
    # for i, (hex_block, orig_bytes) in enumerate(ad10_blocks):
    #     content = orig_bytes.decode('utf-8')
    #     print(f"associated_data[{i}] = 128'h{hex_block}; // \"{content}\"")
    
    # print(f"")
    # print(f'// Ciphertext: {ct10.hex()} ({len(ct10)} bytes)')
    # ct10_blocks = string_to_hex_blocks(ct10)
    # for i, (hex_block, orig_bytes) in enumerate(ct10_blocks):
    #     print(f"ciphertext_data[{i}] = 128'h{hex_block};")
    
    # print(f"")
    # print(f"tag_in = 128'h{tag10.hex()};")
    
    # ad10_total_blocks, ad10_remainder = calculate_blocks_and_remainder(ad10_bytes)
    # ct10_total_blocks, ct10_remainder = calculate_blocks_and_remainder(ct10)
    # print(f"")
    # print(f"run_aead_test(0, {ad10_total_blocks}, {ad10_remainder}, {ct10_total_blocks}, {ct10_remainder}); // decrypt")
    # print(f"// Expected plaintext: {pt10}")
    # print(f"// Should return tag_valid = 1")

    # print("\n" + "=" * 80)
    # print("COPY THESE PATTERNS TO YOUR TESTBENCH!")
    # print("KEY CORRECTIONS:")
    # print("- Test 5: PT is 23 bytes, not 24 - use last_bytes = 7")
    # print("- Test 6: PT is 39 bytes, not 40 - use last_bytes = 7") 
    # print("\nNEW TEST CASES ADDED:")
    # print("- Test 7: 15-byte boundary cases")
    # print("- Test 8: Mixed size multi-block")
    # print("- Test 9: Single byte minimal data")
    # print("- Test 10: Maximum 3-block data")
    # print("\nDECRYPTION TESTS ADDED:")
    # print("- Test 1 Decryption: Basic AEAD")
    # print("- Test 4 Decryption: Full Block AEAD")
    # print("- Test 5 Decryption: Multi-block AEAD")
    # print("- Test 6 Decryption: Large Multi-block AEAD")
    # print("- Test 7 Decryption: 15-byte Boundary Cases")
    # print("- Test 8 Decryption: Mixed Size Multi-block")
    # print("- Test 9 Decryption: Single Byte Data")
    # print("- Test 10 Decryption: Maximum 3-block Test")
    # print("=" * 80)


def test_aead_simple(key_hex, nonce_hex, ad_hex, plaintext_hex):
    """
    Super simple AEAD test - just input data as hex strings.
    
    Args:
        key_hex: 128-bit key as hex string (32 chars)
        nonce_hex: 128-bit nonce as hex string (32 chars) 
        ad_hex: Associated data as hex string
        plaintext_hex: Plaintext as hex string
    
    Returns:
        dict with ciphertext and tag
    """
    print(f"=== SIMPLE AEAD TEST ===")
    
    # Convert hex strings to bytes
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ad = bytes.fromhex(ad_hex) if ad_hex else b""
    plaintext = bytes.fromhex(plaintext_hex) if plaintext_hex else b""
    
    print(f"Key: {key_hex} ({len(key)} bytes)")
    print(f"Nonce: {nonce_hex} ({len(nonce)} bytes)")
    print(f"AD: {ad_hex} ({len(ad)} bytes)")
    print(f"Plaintext: {plaintext_hex} ({len(plaintext)} bytes)")
    
    # Encrypt
    ciphertext, tag = ascon_encrypt(key, nonce, ad, plaintext)
    
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")
    
    # Verify by decrypting
    decrypted = ascon_decrypt(key, nonce, ad, ciphertext + tag)
    valid = (decrypted == plaintext)
    
    print(f"Verification: {'PASS' if valid else 'FAIL'}")
    print(f"Hardware signals:")
    print(f"  expected_ciphertext = {len(ciphertext)*8}'h{ciphertext.hex()};")
    print(f"  expected_tag = 128'h{tag.hex()};")
    
    return {
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
        'valid': valid
    }


def test_hmac_simple():
    """
    Super simple HMAC test - just input key and message as hex strings.
    
    Args:
        key_hex: Key as hex string (e.g., "aabbccdd00000000")
        message_hex: Message as hex string (e.g., "1122334400000000")
    
    Returns:
        Expected HMAC tag as hex string
    """
    print(f"=== SIMPLE HMAC TEST ===")
    
    # Use default test data
    key = b"short test!"
    message = b"Hello, HMAC-ASCON! with a much longer message to test the implementation."

    print(f"Key: {key.hex()} ({len(key)} bytes)")
    print(f"Message: {message.hex()} ({len(message)} bytes)")

    # Determine HMAC case
    if len(key) > 64:
        case = "B (Key > 64 bytes - will be hashed)"
    elif len(key) == 64:
        case = "A (Key = 64 bytes - used directly)"
    else:
        case = "C (Key < 64 bytes - will be padded)"
    
    print(f"HMAC Case: {case}")
    
    # Generate Verilog test data format
    print(f"\n=== Verilog Format ===")
    
    # Key data in Verilog format
    print(f"    // Key: \"{key.decode()}\" ({len(key)} bytes)")
    key_chunks = []
    for i in range(0, len(key), 8):
        chunk = key[i:i+8]
        if len(chunk) < 8:
            chunk = chunk + b'\x00' * (8 - len(chunk))  # Pad with zeros
        key_chunks.append(chunk)
    
    for i, chunk in enumerate(key_chunks):
        chunk_value = int.from_bytes(chunk, byteorder='big')
        valid_bytes = min(8, len(key) - i*8)
        is_last = (i == len(key_chunks) - 1)
        last_comment = " (LAST)" if is_last else ""
        print(f"    key_data[{i}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
    
    # Message data in Verilog format
    print(f"    // Message: \"{message.decode()}\" ({len(message)} bytes)")
    message_chunks = []
    for i in range(0, len(message), 8):
        chunk = message[i:i+8]
        if len(chunk) < 8:
            chunk = chunk + b'\x00' * (8 - len(chunk))  # Pad with zeros
        message_chunks.append(chunk)
    
    for i, chunk in enumerate(message_chunks):
        chunk_value = int.from_bytes(chunk, byteorder='big')
        valid_bytes = min(8, len(message) - i*8)
        is_last = (i == len(message_chunks) - 1)
        last_comment = " (LAST)" if is_last else ""
        print(f"    message_data[{i}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
    
    # Compute HMAC
    tag = hmac_ascon(key, message, "Ascon-Hash256", 32)
    
    print(f"\n=== Complete Testbench Code ===")
    print(f"    // Key: \"{key.decode()}\" ({len(key)} bytes)")
    print(f"    // Expected HMAC tag: {tag.hex()}")
    
    # Print key data
    for i, chunk in enumerate(key_chunks):
        chunk_value = int.from_bytes(chunk, byteorder='big')
        valid_bytes = min(8, len(key) - i*8)
        is_last = (i == len(key_chunks) - 1)
        last_comment = " (LAST)" if is_last else ""
        print(f"    key_data[{i}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
    
    # Print message data
    print(f"    // Message: \"{message.decode()}\" ({len(message)} bytes)")
    for i, chunk in enumerate(message_chunks):
        chunk_value = int.from_bytes(chunk, byteorder='big')
        valid_bytes = min(8, len(message) - i*8)
        is_last = (i == len(message_chunks) - 1)
        last_comment = " (LAST)" if is_last else ""
        print(f"    message_data[{i}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
    
    # Print test execution
    print(f"")
    print(f"    run_hmac_test({len(key)}, {len(message)});")
    print(f"    ")
    print(f"    // Verify the result against expected tag")
    print(f"    verify_hmac_result({len(key)}, {len(message)}, 256'h{tag.hex()});")
    
    print(f"\nExpected tag: {tag.hex()}")
    print(f"Hardware signals:")
    print(f"  hmac_key_size = 10'd{len(key)};")
    print(f"  expected_tag = 256'h{tag.hex()};")
    
    return tag.hex()


def simple_hmac_test(key_chunks, key_last_bytes, msg_chunks, msg_last_bytes):
    """
    Simplified HMAC test with direct chunk and last_byte specification.
    
    Args:
        key_chunks: Number of 8-byte key chunks
        key_last_bytes: Valid bytes in the last key chunk (1-8, or 8 for full chunk)
        msg_chunks: Number of 8-byte message chunks  
        msg_last_bytes: Valid bytes in the last message chunk (1-8, or 8 for full chunk)
    
    Returns:
        dict with test results including expected HMAC tag
    """
    print(f"=== SIMPLE HMAC TEST ===")
    print(f"Key: {key_chunks} chunks, last chunk has {key_last_bytes} valid bytes")
    print(f"Message: {msg_chunks} chunks, last chunk has {msg_last_bytes} valid bytes")
    
    # Calculate total sizes
    key_size_bytes = (key_chunks - 1) * 8 + key_last_bytes if key_chunks > 0 else 0
    msg_size_bytes = (msg_chunks - 1) * 8 + msg_last_bytes if msg_chunks > 0 else 0
    
    print(f"Total key size: {key_size_bytes} bytes")
    print(f"Total message size: {msg_size_bytes} bytes")
    
    # Determine HMAC case
    if key_size_bytes > 64:
        case = "B (Key > 64 bytes - will be hashed)"
    elif key_size_bytes == 64:
        case = "A (Key = 64 bytes - used directly)"
    else:
        case = "C (Key < 64 bytes - will be padded)"
    
    print(f"HMAC Case: {case}")
    
    # Generate key using standard pattern
    key_chunks_data = []
    for i in range(key_chunks):
        chunk_value = 0xAABBCCDD00000000 + i
        chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
        
        # For the last chunk, only take the valid bytes
        if i == key_chunks - 1:
            chunk_bytes = chunk_bytes[:key_last_bytes]
        
        key_chunks_data.append(chunk_bytes)
    
    # Generate message using standard pattern
    msg_chunks_data = []
    for i in range(msg_chunks):
        chunk_value = 0x1122334400000000 + i
        chunk_bytes = chunk_value.to_bytes(8, byteorder='big')
        
        # For the last chunk, only take the valid bytes
        if i == msg_chunks - 1:
            chunk_bytes = chunk_bytes[:msg_last_bytes]
        
        msg_chunks_data.append(chunk_bytes)
    
    # Concatenate to form key and message
    key = b''.join(key_chunks_data)
    message = b''.join(msg_chunks_data)
    
    print(f"\n--- Generated Data ---")
    print(f"Key chunks:")
    for i, chunk in enumerate(key_chunks_data):
        if i == key_chunks - 1 and key_last_bytes < 8:
            print(f"  [{i}] {chunk.hex()} ({key_last_bytes} bytes) LAST")
        else:
            chunk_value = 0xAABBCCDD00000000 + i
            print(f"  [{i}] {chunk.hex()} (64'h{chunk_value:016x})")
    
    print(f"Message chunks:")
    for i, chunk in enumerate(msg_chunks_data):
        if i == msg_chunks - 1 and msg_last_bytes < 8:
            print(f"  [{i}] {chunk.hex()} ({msg_last_bytes} bytes) LAST")
        else:
            chunk_value = 0x1122334400000000 + i
            print(f"  [{i}] {chunk.hex()} (64'h{chunk_value:016x})")
    
    print(f"\nFinal key: {key.hex()}")
    print(f"Final message: {message.hex()}")
    
    # Compute HMAC
    hmac_tag = hmac_ascon(key, message, "Ascon-Hash256", 32)
    
    print(f"\nHMAC result: {hmac_tag.hex()}")
    print(f"Lower 128 bits: {hmac_tag[:16].hex()}")
    print(f"Upper 128 bits: {hmac_tag[16:].hex()}")
    
    # Hardware testbench format
    print(f"\n--- Hardware Testbench Signals ---")
    print(f"hmac_key_size = 10'd{key_size_bytes};")
    print(f"Expected tag_out = 256'h{hmac_tag.hex()};")
    
    return {
        'key_size_bytes': key_size_bytes,
        'message_size_bytes': msg_size_bytes,
        'hmac_case': case[0],  # Just the letter A, B, or C
        'key': key,
        'message': message,
        'tag': hmac_tag,
        'tag_hex': hmac_tag.hex(),
        'tag_lower': hmac_tag[:16].hex(),
        'tag_upper': hmac_tag[16:].hex()
    }


def generate_hmac_test_cases():
    """
    Generate multiple HMAC test cases covering different scenarios:
    - Case A: 64-byte key (used directly)
    - Case B: >64-byte key (hashed first)  
    - Case C: <64-byte key (padded with zeros)
    """
    
    test_cases = [
        {
            'name': 'Case C: Short Key (16 bytes)',
            'key': b"short_hmac_key16",
            'message': b"Short message for testing HMAC-ASCON implementation."
        },
        {
            'name': 'Case C: Medium Key (32 bytes)', 
            'key': b"medium_length_hmac_key_32_bytes",
            'message': b"Medium length message to test HMAC-ASCON with 32-byte key."
        },
        {
            'name': 'Case A: Exact 64-byte Key',
            'key': b"exact_64_byte_hmac_key_for_testing_ascon_implementation_here",
            'message': b"Testing with exactly 64-byte key for HMAC-ASCON Case A."
        },
        {
            'name': 'Case B: Long Key (80 bytes)',
            'key': b"very_long_hmac_key_exceeding_64_bytes_to_test_case_B_implementation_in_ascon",
            'message': b"Testing HMAC-ASCON with key longer than 64 bytes (Case B)."
        },
        {
            'name': 'Case B: Very Long Key (128 bytes)',
            'key': b"extremely_long_hmac_key_for_comprehensive_testing_of_case_B_in_ascon_hmac_implementation_with_128_byte_key_length_total",
            'message': b"Comprehensive test with 128-byte key for HMAC-ASCON Case B verification."
        },
        {
            'name': 'Edge Case: 1-byte Key',
            'key': b"k",
            'message': b"Minimal test case."
        },
        {
            'name': 'Edge Case: Empty Message',
            'key': b"test_key_for_empty_msg",
            'message': b""
        }
    ]
    
    set_debug_level(0)  # Clean output for test generation
    
    print("=" * 60)
    print("HMAC-ASCON COMPREHENSIVE TEST CASES")
    print("=" * 60)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*20} TEST CASE {i}: {test_case['name']} {'='*20}")
        
        key = test_case['key']
        message = test_case['message']
        
        # Determine HMAC case
        if len(key) > 64:
            case_type = "B (Key > 64 bytes - will be hashed)"
        elif len(key) == 64:
            case_type = "A (Key = 64 bytes - used directly)"
        else:
            case_type = "C (Key < 64 bytes - will be padded)"
        
        print(f"Key: \"{key.decode('ascii', errors='replace')}\" ({len(key)} bytes)")
        print(f"Message: \"{message.decode('ascii', errors='replace')}\" ({len(message)} bytes)")
        print(f"HMAC Case: {case_type}")
        
        # Calculate HMAC
        tag = hmac_ascon(key, message, "Ascon-Hash256", 32)
        
        print(f"\n=== Verilog Testbench Code ===")
        print(f"    // {test_case['name']}")
        print(f"    // Key: \"{key.decode('ascii', errors='replace')}\" ({len(key)} bytes)")
        print(f"    // Message: \"{message.decode('ascii', errors='replace')}\" ({len(message)} bytes)")
        print(f"    // Expected HMAC tag: {tag.hex()}")
        
        # Generate key data
        key_chunks = []
        for j in range(0, len(key), 8):
            chunk = key[j:j+8]
            if len(chunk) < 8:
                chunk = chunk + b'\x00' * (8 - len(chunk))
            key_chunks.append(chunk)
        
        for j, chunk in enumerate(key_chunks):
            chunk_value = int.from_bytes(chunk, byteorder='big')
            valid_bytes = min(8, len(key) - j*8)
            is_last = (j == len(key_chunks) - 1)
            last_comment = " (LAST)" if is_last else ""
            print(f"    key_data[{j}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
        
        # Generate message data
        if len(message) > 0:
            message_chunks = []
            for j in range(0, len(message), 8):
                chunk = message[j:j+8]
                if len(chunk) < 8:
                    chunk = chunk + b'\x00' * (8 - len(chunk))
                message_chunks.append(chunk)
            
            for j, chunk in enumerate(message_chunks):
                chunk_value = int.from_bytes(chunk, byteorder='big')
                valid_bytes = min(8, len(message) - j*8)
                is_last = (j == len(message_chunks) - 1)
                last_comment = " (LAST)" if is_last else ""
                print(f"    message_data[{j}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
        else:
            print(f"    // Empty message - no message_data needed")
        
        # Test execution code
        print(f"")
        print(f"    run_hmac_test({len(key)}, {len(message)});")
        print(f"    verify_hmac_result({len(key)}, {len(message)}, 256'h{tag.hex()});")
        
        print(f"\nExpected tag: {tag.hex()}")
        print(f"Hardware signals: hmac_key_size = 10'd{len(key)}; expected_tag = 256'h{tag.hex()};")


def test_cxof_cases():
    """
    Golden reference test for ASCON-CXOF 
    This generates the correct expected values that hardware should match
    """
    print("\n" + "=" * 80)
    print("ASCON-CXOF GOLDEN REFERENCE TEST")
    print("=" * 80)
    
    # Disable debug output for clean golden results
    set_debug_level(0)
    
    # Test 1: 4-byte custom "test" + 4-byte message "data" + 2 blocks (16 bytes)
    custom = b"test"
    message = b"data"
    output_len = 16
    
    print(f"Test 1: ASCON-CXOF Golden Reference")
    print(f"Custom: {custom} ({len(custom)} bytes)")
    print(f"Message: {message} ({len(message)} bytes)")
    print(f"Output length: {output_len} bytes")
    print()
    
    try:
        result = ascon_hash(message, variant="Ascon-CXOF128", 
                          hashlength=output_len, customization=custom)
        print(f"Golden Expected: {result.hex()}")
        print(f"Testbench should use: $display(\"Expected: {result.hex()}\");")
        
        # Generate Verilog data blocks
        generate_cxof_verilog_data(custom, message, output_len, result)
        
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("=" * 80)

def test_cxof_1_block_custom():
    """
    CXOF test for hardware with the CORRECT pattern format as specified by user:
    custom_data[0] = size in bits (not bytes)
    custom_data[1]+ = actual customization data blocks
    test_ascon_cxof(11, 4, 2) call format
    """
    print("\n" + "=" * 80)
    print("ASCON-CXOF HARDWARE TEST - CORRECT PATTERN")
    print("=" * 80)
    
    # Disable debug output for clean results  
    set_debug_level(0)
    
    # Test with short customization for 1 data block
    custom = b"key"  # 3 bytes
    message = b"data"  # 4 bytes
    output_len = 16  # 2 blocks
    
    print(f"Customization: \"{custom.decode()}\" ({len(custom)} bytes)")
    print(f"Message: \"{message.decode()}\" ({len(message)} bytes)")
    print(f"Output length: {output_len} bytes")
    print()
    
    # Calculate expected result using ASCON-CXOF128
    try:
        expected_result = ascon_hash(message, variant="Ascon-CXOF128", 
                                   hashlength=output_len, customization=custom)
        print(f"Expected Result: {expected_result.hex()}")
        print()
        
        # Generate the CORRECT Verilog pattern as shown by user
        print("$display(\"\\n=== TESTING ASCON-CXOF MODES ===\");")
        print()
        print("// Customization size and data:")
        
        # Size in bits, in MSB-first format as expected by hardware
        custom_size_bits = len(custom) * 8
        # For hardware, put the size in the MSB position
        size_value = custom_size_bits << 56  # Shift to MSB position 
        print(f"custom_data[0] = 64'h{size_value:016x}; // Size: {len(custom)} bytes")
        
        # Pad custom data to 8-byte blocks
        custom_padded = custom + b'\x00' * (8 - (len(custom) % 8)) if len(custom) % 8 != 0 else custom
        for i in range(0, len(custom_padded), 8):
            chunk = custom_padded[i:i+8]
            chunk_value = int.from_bytes(chunk, byteorder='big')
            block_idx = (i // 8) + 1  # Start from index 1
            if i + 8 >= len(custom):
                valid_bytes = len(custom) - i
                print(f"custom_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{custom[i:i+valid_bytes].decode()}\" + padding")
            else:
                print(f"custom_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{custom[i:i+8].decode()}\"")
        
        total_custom_blocks = 1 + ((len(custom) + 7) // 8)  # Size block + data blocks
        print(f"// Total custom blocks: {total_custom_blocks} (1 size + {total_custom_blocks-1} data)")
        print()
        
        # Message data format
        print(f"// Message data:")
        message_padded = message + b'\x00' * (8 - (len(message) % 8)) if len(message) % 8 != 0 else message
        for i in range(0, len(message_padded), 8):
            chunk = message_padded[i:i+8]
            chunk_value = int.from_bytes(chunk, byteorder='big')
            block_idx = i // 8
            if i + 8 >= len(message):
                valid_bytes = len(message) - i
                print(f"message_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{message[i:i+valid_bytes].decode()}\" + padding")
            else:
                print(f"message_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{message[i:i+8].decode()}\"")
        
        message_blocks = (len(message) + 7) // 8
        print(f"// Total message blocks: {message_blocks}")
        print()
        
        # Test call with the CORRECT parameters as shown by user
        print(f"// Test call:")
        print(f"test_ascon_cxof(11, 4, 2);")
        print()
        
        # Expected output
        print(f"// Expected output:")
        for i in range(0, output_len, 8):
            chunk = expected_result[i:i+8]
            chunk_value = int.from_bytes(chunk, byteorder='big')
            print(f"expected_output[{i//8}] = 64'h{chunk_value:016x};")
        
        print()
        print(f"$display(\"Expected: {expected_result.hex()}\");")
        
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("=" * 80)

def generate_cxof_verilog_data(custom, message, output_len, expected_result):
    """
    Generate Verilog data blocks for CXOF test cases
    Following ASCON-CXOF128 specification:
    Z0 = int64(|Z|) - length in bits
    Z1, ..., Zm = customization string + padding
    """
    print(f"\n// === Verilog Test Data Generation ===")
    
    # Generate customization data blocks per CXOF specification
    print(f"// CXOF Customization Format (per specification):")
    print(f"// Z0 = int64(|Z|) = length in bits")
    print(f"// Z1, ..., Zm = customization string + padding")
    print(f"// Customization: \"{custom.decode()}\" ({len(custom)} bytes = {len(custom)*8} bits)")
    
    rate = 8  # 64 bits = 8 bytes
    
    # Step 1: Z0 = int64(|Z|) - length in bits as first 64-bit block
    z_length_bits = len(custom) * 8
    z0 = z_length_bits.to_bytes(8, byteorder='big')
    z0_value = int.from_bytes(z0, byteorder='big')
    print(f"custom_data[0] = 64'h{z0_value:016x}; // Z0 = length in bits ({z_length_bits})")
    
    # Step 2: Z1, ..., Zm = customization string + padding
    z_padding = bytes([0x01]) + bytes(rate - (len(custom) % rate) - 1)
    z_padded_content = custom + z_padding
    
    # Convert to 64-bit blocks
    block_index = 1
    for i in range(0, len(z_padded_content), 8):
        chunk = z_padded_content[i:i+8]
        if len(chunk) < 8:
            chunk = chunk + b'\x00' * (8 - len(chunk))
        chunk_value = int.from_bytes(chunk, byteorder='big')
        
        # Determine what this block contains
        if i == 0 and len(z_padded_content) <= 8:
            content_desc = f"Z{block_index} = \"{custom.decode()}\" + padding"
        elif i == 0:
            content_desc = f"Z{block_index} = first part of \"{custom.decode()}\""
        else:
            content_desc = f"Z{block_index} = continuation/padding"
            
        print(f"custom_data[{block_index}] = 64'h{chunk_value:016x}; // {content_desc}")
        block_index += 1
    
    total_custom_blocks = block_index
    print(f"// Total customization blocks: {total_custom_blocks}")
    print()
    
    # Generate message data blocks (unchanged)
    print(f"// Message: \"{message.decode()}\" ({len(message)} bytes)")
    message_blocks = []
    for i in range(0, len(message), 8):
        chunk = message[i:i+8]
        if len(chunk) < 8:
            chunk = chunk + b'\x00' * (8 - len(chunk))  # Pad with zeros
        message_blocks.append(chunk)
    
    for i, chunk in enumerate(message_blocks):
        chunk_value = int.from_bytes(chunk, byteorder='big')
        valid_bytes = min(8, len(message) - i*8)
        is_last = (i == len(message_blocks) - 1)
        last_comment = " (LAST)" if is_last else ""
        print(f"message_data[{i}] = 64'h{chunk_value:016x}; // {valid_bytes} bytes{last_comment}")
    
    print()
    
    # Generate test call parameters
    # NOTE: For CXOF, we need to pass the TOTAL customization blocks (including Z0)
    custom_byte_count = len(custom)  # Original customization length for the hardware
    message_byte_count = len(message)
    output_blocks = output_len // 8
    
    print(f"// Test call parameters:")
    print(f"// NOTE: Hardware should handle CXOF format internally")
    print(f"test_ascon_cxof({custom_byte_count}, {message_byte_count}, {output_blocks});")
    print(f"// Or if hardware expects block counts:")
    print(f"// test_ascon_cxof_blocks({total_custom_blocks}, {len(message_blocks)}, {output_blocks});")
    
    # Generate expected output blocks
    print(f"// Expected output ({output_len} bytes = {output_blocks} blocks):")
    for i in range(0, output_len, 8):
        chunk = expected_result[i:i+8]
        chunk_value = int.from_bytes(chunk, byteorder='big')
        print(f"expected_output[{i//8}] = 64'h{chunk_value:016x};")
    
    print(f"// Expected concatenated: {expected_result.hex()}")
    print(f"$display(\"Expected: {expected_result.hex()}\");")
    print()

def generate_multiple_cxof_tests():
    """
    Generate multiple CXOF test cases with different customization and message patterns.
    All test cases use meaningful (non-empty) customization and message data.
    """
    print("\n" + "=" * 80)
    print("MULTIPLE ASCON-CXOF TEST CASES GENERATION")
    print("=" * 80)
    
    # Disable debug output for clean test generation
    set_debug_level(0)
    
    test_cases = [
        {
            'name': 'Test Case 1: Short custom + Short message',
            'custom': b"key",      # 3 bytes
            'message': b"data",    # 4 bytes
            'output_len': 16,      # 2 blocks
        },
        {
            'name': 'Test Case 2: Medium custom + Medium message', 
            'custom': b"test_key",     # 8 bytes (exactly 1 block)
            'message': b"test_msg",    # 8 bytes (exactly 1 block)
            'output_len': 24,          # 3 blocks
        },
        {
            'name': 'Test Case 3: Long custom + Short message',
            'custom': b"authentication_key",  # 18 bytes (>1 block)
            'message': b"hello",              # 5 bytes
            'output_len': 32,                 # 4 blocks
        },
        {
            'name': 'Test Case 4: Short custom + Long message',
            'custom': b"id",                    # 2 bytes
            'message': b"this_is_a_test_msg",  # 18 bytes (>1 block)
            'output_len': 16,                  # 2 blocks
        },
        {
            'name': 'Test Case 5: Alphanumeric patterns',
            'custom': b"abc123",        # 6 bytes
            'message': b"xyz789",       # 6 bytes  
            'output_len': 24,           # 3 blocks
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*60}")
        print(f"{test_case['name']}")
        print(f"{'='*60}")
        
        custom = test_case['custom']
        message = test_case['message']
        output_len = test_case['output_len']
        
        # Calculate correct test parameters
        # First parameter: 8 (size block) + custom data size
        # Second parameter: message size in bytes
        # Third parameter: output size in blocks
        custom_total_bytes = 8 + len(custom)  # 8 bytes for size + actual custom data
        message_bytes = len(message)
        output_blocks = output_len // 8
        test_params = (custom_total_bytes, message_bytes, output_blocks)
        
        print(f"Customization: \"{custom.decode()}\" ({len(custom)} bytes)")
        print(f"Message: \"{message.decode()}\" ({len(message)} bytes)")
        print(f"Output length: {output_len} bytes")
        print(f"Total custom input: 8 (size block) + {len(custom)} (data) = {custom_total_bytes} bytes")
        print()
        
        try:
            # Calculate expected result using ASCON-CXOF128
            expected_result = ascon_hash(message, variant="Ascon-CXOF128", 
                                       hashlength=output_len, customization=custom)
            
            print(f"Expected Result: {expected_result.hex()}")
            print()
            
            # Generate Verilog testbench code
            print("// === Verilog Testbench Code ===")
            print(f"$display(\"\\n=== {test_case['name'].upper()} ===\");")
            print()
            
            # Generate customization data
            print("// Customization size and data:")
            custom_size_bits = len(custom) * 8
            size_value = custom_size_bits << 56  # Shift to MSB position for hardware
            print(f"custom_data[0] = 64'h{size_value:016x}; // Size: {len(custom)} bytes")
            
            # Pad custom data to 8-byte blocks
            custom_padded = custom + b'\x00' * (8 - (len(custom) % 8)) if len(custom) % 8 != 0 else custom
            for j in range(0, len(custom_padded), 8):
                chunk = custom_padded[j:j+8]
                chunk_value = int.from_bytes(chunk, byteorder='big')
                block_idx = (j // 8) + 1
                if j + 8 >= len(custom):
                    valid_bytes = len(custom) - j
                    print(f"custom_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{custom[j:j+valid_bytes].decode()}\" + padding")
                else:
                    print(f"custom_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{custom[j:j+8].decode()}\"")
            
            total_custom_blocks = 1 + ((len(custom) + 7) // 8)
            print(f"// Total custom blocks: {total_custom_blocks} (1 size + {total_custom_blocks-1} data)")
            print()
            
            # Generate message data
            print("// Message data:")
            message_padded = message + b'\x00' * (8 - (len(message) % 8)) if len(message) % 8 != 0 else message
            for j in range(0, len(message_padded), 8):
                chunk = message_padded[j:j+8]
                chunk_value = int.from_bytes(chunk, byteorder='big')
                block_idx = j // 8
                if j + 8 >= len(message):
                    valid_bytes = len(message) - j
                    print(f"message_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{message[j:j+valid_bytes].decode()}\" + padding")
                else:
                    print(f"message_data[{block_idx}] = 64'h{chunk_value:016x}; // \"{message[j:j+8].decode()}\"")
            
            message_blocks = (len(message) + 7) // 8
            print(f"// Total message blocks: {message_blocks}")
            print()
            
            # Generate expected output
            print("// Expected output:")
            for j in range(0, output_len, 8):
                chunk = expected_result[j:j+8]
                chunk_value = int.from_bytes(chunk, byteorder='big')
                print(f"expected_output[{j//8}] = 64'h{chunk_value:016x};")
            
            print()
            print(f"$display(\"Expected: {expected_result.hex()}\");")
            print()
            
            # Generate test call
            print("// Test call:")
            print(f"// Parameters: 8+custom_size({custom_total_bytes}), message_bytes({message_bytes}), output_blocks({output_blocks})")
            print(f"test_ascon_cxof_verify({test_params[0]}, {test_params[1]}, {test_params[2]});")
            print()
            
        except Exception as e:
            print(f"ERROR: {e}")
    
    print("\n" + "=" * 80)
    print("ALL CXOF TEST CASES GENERATED SUCCESSFULLY")
    print("=" * 80)

def generate_hmac_testbench_pattern(key, message, test_name="HMAC Test"):
    """
    Generate Verilog testbench pattern for HMAC-ASCON test.
    Matches the format of ascon_top_tb_simple.v exactly.
    
    Args:
        key: Key as bytes or string
        message: Message as bytes or string
        test_name: Optional name for the test
    
    Returns:
        None (prints Verilog testbench pattern)
    """
    # Convert strings to bytes if needed
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Compute HMAC tag
    tag = hmac_ascon(key, message)
    
    # Calculate number of 64-bit words needed (pad to 8-byte boundary)
    key_bytes = key + b'\x00' * ((8 - len(key) % 8) % 8)
    msg_bytes = message + b'\x00' * ((8 - len(message) % 8) % 8)
    
    num_key_words = len(key_bytes) // 8
    num_msg_words = len(msg_bytes) // 8
    
    # Helper function to format bytes as ASCII display
    def format_ascii(data, max_len=16):
        """Format bytes as printable ASCII, truncating if needed."""
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:max_len])
        if len(data) > max_len:
            printable += '...'
        return printable
    
    # Determine comment based on key size
    if len(key) > 64:
        comment = "Key size > 64 bytes (requires key hashing)"
    elif len(key) == 64:
        comment = "Key size = 64 bytes (boundary case, no hashing)"
    else:
        comment = "Key size < 64 bytes (no hashing required)"
    
    print("")
    print("    // ========================================")
    print(f"    // {test_name.upper()}: {comment}")
    print("    // ========================================")
    print("    $display(\"\\n--- {}: HMAC ({}-byte key, {}-byte message) ---\");".format(
        test_name, len(key), len(message)))
    print("")
    
    # Generate config and start FIRST
    print("    @(posedge clk);")
    print(f"    config_in = {{50'd{len(message)}, 10'd{len(key)}, 1'b1, MODE_HMAC}};  " +
          f"// msg_size={len(message)}, key_size={len(key)}, start=1, mode=100")
    print("    @(posedge clk);")
    print("")
    print("    // Clear start bit")
    print(f"    config_in = {{50'd{len(message)}, 10'd{len(key)}, 1'b0, MODE_HMAC}};")
    print("    ")
    
    # Generate key writes
    print("    // Write key to FIFO: \"{}\" ({} bytes = {} chunks)".format(
        format_ascii(key), len(key), num_key_words))
    print("    $display(\"[TB] Writing key to FIFO...\");")
    
    for i in range(num_key_words):
        chunk = key_bytes[i*8:(i+1)*8]
        value = int.from_bytes(chunk, 'big')
        chunk_ascii = format_ascii(chunk, 8)
        
        print("    repeat(10) @(posedge clk);")
        print(f"    fifo_wr_data = 64'h{value:016x}; // \"{chunk_ascii}\"")
        print("    fifo_wr_en = 1;")
        print("    @(posedge clk);")
        print("    fifo_wr_en = 0;")
        if i < num_key_words - 1:  # Add blank line between chunks except last
            print("")
    
    print("")
    
    # Generate message writes
    print("    // Write message to FIFO: \"{}\" ({} bytes = {} chunks)".format(
        format_ascii(message), len(message), num_msg_words))
    print("    $display(\"[TB] Writing message to FIFO...\");")
    
    for i in range(num_msg_words):
        chunk = msg_bytes[i*8:(i+1)*8]
        value = int.from_bytes(chunk, 'big')
        chunk_ascii = format_ascii(chunk, 8)
        
        print("    repeat(10) @(posedge clk);")
        print(f"    fifo_wr_data = 64'h{value:016x}; // \"{chunk_ascii}\"")
        print("    fifo_wr_en = 1;")
        print("    @(posedge clk);")
        print("    fifo_wr_en = 0;")
        if i < num_msg_words - 1:  # Add blank line between chunks except last
            print("")
    
    print("")
    
    # Print expected output
    tag_int = int.from_bytes(tag, 'big')
    print(f"    // Expected HMAC tag: {tag.hex()}")
    print(f"    // Expected tag_out: 256'h{tag_int:064x}")
    print("")
    
    # Print summary
    print(f"    // Summary: Key={len(key)}B ({num_key_words} chunks), " +
          f"Msg={len(message)}B ({num_msg_words} chunks), Tag=32B (256 bits)")
    print("")

def generate_multiple_hmac_tests():
    """
    Generate multiple HMAC test patterns with various key and message sizes.
    """
    test_cases = [
        {
            'name': 'Test 1: Minimal 8-byte key and message',
            'key': b'12345678',
            'message': b'ABCDEFGH'
        },
        {
            'name': 'Test 2: 11-byte key, 18-byte message',
            'key': b'HelloWorld!',
            'message': b'This is a test msg'
        },
        {
            'name': 'Test 3: 16-byte key (full block), 32-byte message',
            'key': b'0123456789ABCDEF',
            'message': b'This is exactly 32 bytes!!!!'
        },
        {
            'name': 'Test 4: 31-byte key, 60-byte message',
            'key': b'This_is_a_31_byte_key_value',
            'message': b'This is exactly sixty bytes of message data for testing!'
        },
        {
            'name': 'Test 5: 64-byte key (boundary), 64-byte message',
            'key': b'A' * 64,
            'message': b'B' * 64
        },
        {
            'name': 'Test 6: Large key (requires hashing), multi-block message',
            'key': b'This is a very long key that exceeds 64 bytes and will be hashed first!',
            'message': b'This is a very long message that spans multiple blocks and requires multiple permutations!'
        }
    ]
    
    print("\n" + "="*80)
    print("HMAC-ASCON VERILOG TESTBENCH PATTERNS")
    print("="*80)
    print("")
    
    for test in test_cases:
        generate_hmac_testbench_pattern(test['key'], test['message'], test['name'])
    
    print("\n" + "="*80)
    print("ALL HMAC TEST PATTERNS GENERATED")
    print("="*80)

if __name__ == "__main__":
    # test_cxof_cases()
    # test_cxof_1_block_custom()
    # generate_multiple_cxof_tests()
    # generate_aead_testbench_cases()
    # test_exact_testbench_case5()
    
    demo_hash()
    # generate_hmac_testbench_pattern(
    #key=b'HelloWorld',
    #message=b'This is a test msg',
    #test_name='My Test'
    #)
        
#     generate_hmac_testbench_pattern(
#     key=b'HMAC_Authentication_Secret_Key_For_Testing_Boundary_Case_XXXXXXX',
#     message=b'Test for exactly 64-byte key boundary.',
#     test_name='My Test'
# )
    
    # generate_verilog_testbench_patterns()
    # print("Running comprehensive ASCON AEAD test replication...")
    # generate_verilog_testbench_patterns()
    # print("\n" + "="*80)
    # print("DETAILED TEST RESULTS FOR DEBUGGING:")
    # print("="*80)
    # replicate_all_testbench_cases()
