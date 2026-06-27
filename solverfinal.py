#!/usr/bin/env python3

import time

CHALLENGE2 = {
    "name": "Challenge 2 — sharafu{} cipher",
    "KEY_SBOX": [
        211, 243, 147, 179, 83, 115, 19, 51, 210, 242, 146, 178, 82, 114, 18, 50,
        209, 241, 145, 177, 81, 113, 17, 49, 208, 240, 144, 176, 80, 112, 16, 48,
        215, 247, 151, 183, 87, 119, 23, 55, 214, 246, 150, 182, 86, 118, 22, 54,
        213, 245, 149, 181, 85, 117, 21, 53, 212, 244, 148, 180, 84, 116, 20, 52,
        219, 251, 155, 187, 91, 123, 27, 59, 218, 250, 154, 186, 90, 122, 26, 58,
        217, 249, 153, 185, 89, 121, 25, 57, 216, 248, 152, 184, 88, 120, 24, 56,
        223, 255, 159, 191, 95, 127, 31, 63, 222, 254, 158, 190, 94, 126, 30, 62,
        221, 253, 157, 189, 93, 125, 29, 61, 220, 252, 156, 188, 92, 124, 28, 60,
        195, 227, 131, 163, 67, 99, 3, 35, 194, 226, 130, 162, 66, 98, 2, 34,
        193, 225, 129, 161, 65, 97, 1, 33, 192, 224, 128, 160, 64, 96, 0, 32,
        199, 231, 135, 167, 71, 103, 7, 39, 198, 230, 134, 166, 70, 102, 6, 38,
        197, 229, 133, 165, 69, 101, 5, 37, 196, 228, 132, 164, 68, 100, 4, 36,
        203, 235, 139, 171, 75, 107, 11, 43, 202, 234, 138, 170, 74, 106, 10, 42,
        201, 233, 137, 169, 73, 105, 9, 41, 200, 232, 136, 168, 72, 104, 8, 40,
        207, 239, 143, 175, 79, 111, 15, 47, 206, 238, 142, 174, 78, 110, 14, 46,
        205, 237, 141, 173, 77, 109, 13, 45, 204, 236, 140, 172, 76, 108, 12, 44
    ],
    "PBOX": [
        41, 214, 131, 48, 221, 138, 55, 228, 145, 62, 235, 152, 69, 242, 159, 76,
        249, 166, 83, 0, 173, 90, 7, 180, 97, 14, 187, 104, 21, 194, 111, 28,
        201, 118, 35, 208, 125, 42, 215, 132, 49, 222, 139, 56, 229, 146, 63, 236,
        153, 70, 243, 160, 77, 250, 167, 84, 1, 174, 91, 8, 181, 98, 15, 188,
        105, 22, 195, 112, 29, 202, 119, 36, 209, 126, 43, 216, 133, 50, 223, 140,
        57, 230, 147, 64, 237, 154, 71, 244, 161, 78, 251, 168, 85, 2, 175, 92,
        9, 182, 99, 16, 189, 106, 23, 196, 113, 30, 203, 120, 37, 210, 127, 44,
        217, 134, 51, 224, 141, 58, 231, 148, 65, 238, 155, 72, 245, 162, 79, 252,
        169, 86, 3, 176, 93, 10, 183, 100, 17, 190, 107, 24, 197, 114, 31, 204,
        121, 38, 211, 128, 45, 218, 135, 52, 225, 142, 59, 232, 149, 66, 239, 156,
        73, 246, 163, 80, 253, 170, 87, 4, 177, 94, 11, 184, 101, 18, 191, 108,
        25, 198, 115, 32, 205, 122, 39, 212, 129, 46, 219, 136, 53, 226, 143, 60,
        233, 150, 67, 240, 157, 74, 247, 164, 81, 254, 171, 88, 5, 178, 95, 12,
        185, 102, 19, 192, 109, 26, 199, 116, 33, 206, 123, 40, 213, 130, 47, 220,
        137, 54, 227, 144, 61, 234, 151, 68, 241, 158, 75, 248, 165, 82, 255, 172,
        89, 6, 179, 96, 13, 186, 103, 20, 193, 110, 27, 200, 117, 34, 207, 124
    ],
    "has_padding": True,
}


def check_linearity(KEY_SBOX):
    print("\n[STEP 1] Checking if S Box is linear/affine over GF(2)")
    print("         Testing all 65,536 pairs (a, b) for the affine property:")
    print("         KEY_SBOX[a XOR b] == KEY_SBOX[a] XOR KEY_SBOX[b] XOR KEY_SBOX[0]")

    failures = 0
    constant = KEY_SBOX[0]

    for a in range(256):
        for b in range(256):
            left_side  = KEY_SBOX[a ^ b]
            right_side = KEY_SBOX[a] ^ KEY_SBOX[b] ^ constant
            if left_side != right_side:
                failures += 1

    if failures == 0:
        print(f"         ZERO failures and S Box IS affine over GF(2)!!!")
        print(f"         Entire cipher is linear  attack WILL workkk.")
        return True
    else:
        print(f"         {failures} failures — S-Box is NOT affine.")
        print(f"         This attack does NOT apply to this cipher.")
        return False


def apply_permutation(data, PBOX):
    out = bytearray(32)
    for bit_in in range(256):
        bit_out = PBOX[bit_in]

        in_byte  = bit_in  >> 3 
        in_pos   = 7 - (bit_in  & 7)
        out_byte = bit_out >> 3
        out_pos  = 7 - (bit_out & 7)

        if data[in_byte] & (1 << in_pos):
            out[out_byte] |= (1 << out_pos)

    return bytes(out)


def encrypt_block(block, key, KEY_SBOX, PBOX):
    
    sbox = [KEY_SBOX[i] ^ key[0] for i in range(256)]

    b = bytearray(block)

    for _ in range(100):
        b = bytes([sbox[x] for x in b])

        b = apply_permutation(b, PBOX)

        b = bytes([b[i] ^ key[i] for i in range(32)])

    return bytes(b)


def pad_data(data):
    if len(data) % 32 == 0:
        return data
    diff = 32 - (len(data) % 32)
    return data + bytes([diff] * diff)


def simulate_securehash(plaintext, KEY_SBOX, PBOX):
    data = pad_data(plaintext)
    state = bytes(32)

    for i in range(0, len(data), 32):
        block = data[i:i+32]
        key   = block 
        ct    = encrypt_block(block, key, KEY_SBOX, PBOX)
        state = bytes([state[j] ^ ct[j] for j in range(32)])

    return state

def build_gf2_matrix(KEY_SBOX, PBOX):

    print("\n[STEP 2] Building the 256×256 GF(2) affine map.")
    print("         This requires 257 test encryptions.")
    print("         (1 for the constant d, then 256 for matrix columns)")

    t_start = time.time()

    zero_block = bytes(32)
    d_bytes = encrypt_block(zero_block, zero_block, KEY_SBOX, PBOX)

    d_bits = []
    for byte_val in d_bytes:
        for bit_pos in range(7, -1, -1):
            d_bits.append((byte_val >> bit_pos) & 1)

    A = [[0] * 256 for _ in range(256)]

    for col in range(256):
        ej = bytearray(32)
        ej[col // 8] = 1 << (7 - col % 8) 
        ej = bytes(ej)

        T_ej_bytes = encrypt_block(ej, ej, KEY_SBOX, PBOX)

        byte_idx = 0
        for row_byte in range(32):
            diff = T_ej_bytes[row_byte] ^ d_bytes[row_byte]
            for bit_pos in range(7, -1, -1):
                row = byte_idx
                A[row][col] = (diff >> bit_pos) & 1
                byte_idx += 1

    elapsed = time.time() - t_start
    print(f"         Matrix built in {elapsed:.2f} seconds")
    print(f"         A is 256×256 ({256*256} entries), d is 256 bits")

    return A, d_bits


def pack_augmented_row(matrix_row_bits, rhs_bit):
    
    val = rhs_bit
    for col, b in enumerate(matrix_row_bits):
        if b:
            val |= (1 << (256 - col)) 
    return val


def gaussian_elimination_gf2(A, d_bits, target_bits):
    print("\n[STEP 3] Running gaussian elimination over GF(2)")
    print("         Solving 256 equations × 256 unknowns")

    rhs = [target_bits[i] ^ d_bits[i] for i in range(256)]

    rows = [pack_augmented_row(A[i], rhs[i]) for i in range(256)]

    pivot_for_col = {}    
    free_cols     = []

    used_as_pivot = set()

    for col in range(256):
        col_bit = 1 << (256 - col)

        pivot_row = None
        for r in range(256):
            if r not in used_as_pivot and (rows[r] & col_bit):
                pivot_row = r
                break

        if pivot_row is None:
            free_cols.append(col)
            continue

        pivot_for_col[col] = pivot_row
        used_as_pivot.add(pivot_row)

        pivot_val = rows[pivot_row]
        for r in range(256):
            if r != pivot_row and (rows[r] & col_bit):
                rows[r] ^= pivot_val   # GF(2) subtraction = XOR

    print(f"         Pivots found: {len(pivot_for_col)}")
    print(f"         Free variables: {len(free_cols)} "
          f"(gives 2^{len(free_cols)} = {2**len(free_cols)} solutions to check)")

    solutions = []
    num_free  = len(free_cols)

    for mask in range(2 ** num_free):
        free_vals = {free_cols[i]: (mask >> i) & 1 for i in range(num_free)}

        x_bits = [0] * 256

        for col, val in free_vals.items():
            x_bits[col] = val

        for col, pivot_row in pivot_for_col.items():
            rhs_bit = rows[pivot_row] & 1

            for fc, fv in free_vals.items():
                if fv and (rows[pivot_row] & (1 << (256 - fc))):
                    rhs_bit ^= 1   # GF(2): flip the bit

            x_bits[col] = rhs_bit

        x_bytes = bytearray(32)
        for i, bit in enumerate(x_bits):
            if bit:
                x_bytes[i // 8] |= (1 << (7 - i % 8))

        solutions.append(bytes(x_bytes))

    return solutions

def strip_padding(data):

    if not data:
        return None, 0

    last_byte = data[-1]

    if last_byte == 0:
        return data, 0

    if last_byte >= 32:
        return data, 0 

    pad_len = last_byte
    # Verify all padding bytes match
    for i in range(1, pad_len + 1):
        if data[-i] != last_byte:
            return None, 0 

    return data[:-pad_len], pad_len


def identify_flag(solution_bytes, target, has_padding, KEY_SBOX, PBOX):

    computed = encrypt_block(solution_bytes, solution_bytes, KEY_SBOX, PBOX)
    if computed != target:
        return False, None, "failed verification"

    try:
        raw_text = solution_bytes.decode('ascii')
        if all(32 <= ord(c) <= 126 for c in raw_text):
            return True, raw_text, "32-byte flag (no padding)"
    except (UnicodeDecodeError, ValueError):
        pass

    if has_padding:
        unpadded, pad_len = strip_padding(solution_bytes)
        if unpadded is not None and len(unpadded) > 0:
            try:
                flag_text = unpadded.decode('ascii')
                if all(32 <= ord(c) <= 126 for c in flag_text):
                    return True, flag_text, f"padded flag ({pad_len} pad bytes stripped)"
            except (UnicodeDecodeError, ValueError):
                pass

    if computed == target:
        return True, None, "valid hash but non-printable bytes"

    return False, None, "not a match"


def bytes_to_bits(data):
    bits = []
    for byte_val in data:
        for bit_pos in range(7, -1, -1):
            bits.append((byte_val >> bit_pos) & 1)
    return bits


def solve(cipher_config):
    
    print("=" * 70)
    print(f"  SOLVER: {cipher_config['name']}")
    print("=" * 70)
    print(f"  Target hash: {cipher_config['target']}")

    KEY_SBOX    = cipher_config["KEY_SBOX"]
    PBOX        = cipher_config["PBOX"]
    target_hex  = cipher_config["target"]
    has_padding = cipher_config["has_padding"]

    target_bytes = bytes.fromhex(target_hex)
    target_bits  = bytes_to_bits(target_bytes)

    is_linear = check_linearity(KEY_SBOX)
    if not is_linear:
        print("\n  ✗ S-Box is NOT linear. This attack will not work.")
        print("    Try a different approach for this cipher.")
        return None

    total_start = time.time()

    A, d_bits = build_gf2_matrix(KEY_SBOX, PBOX)

    candidates = gaussian_elimination_gf2(A, d_bits, target_bits)

    print(f"\n[STEP 4] Verifying {len(candidates)} candidate solution(s)...")

    flag_found = None

    for i, candidate in enumerate(candidates):
        valid, flag_text, reason = identify_flag(
            candidate, target_bytes, has_padding, KEY_SBOX, PBOX
        )

        print(f"\n         Candidate {i+1}/{len(candidates)}:")
        print(f"           Hex:    {candidate.hex()}")
        print(f"           Valid:  {valid}")
        print(f"           Reason: {reason}")

        if valid and flag_text:
            print(f"\n         ╔══════════════════════════════════════╗")
            print(f"         ║   Decrypted                       ║")
            print(f"         ║  {flag_text:<38}  ║")
            print(f"         ╚══════════════════════════════════════╝")
            flag_found = flag_text

        elif valid and not flag_text:
            print(f"           Note: Hash verified but bytes aren't printable ASCII.")
            print(f"           Raw hex: {candidate.hex()}")

    total_elapsed = time.time() - total_start
    print(f"\n  Total solver time: {total_elapsed:.2f} seconds")
    print("=" * 70)

    return flag_found

def main():

    print("=" * 70)
    print("  Affine GF(2) Cipher Solver")
    print("=" * 70)
    print()
    print("Paste a digest generated by the vulnerable cipher.")
    print()

    target = input("Target digest (64 hex chars): ").strip()

    if len(target) != 64:
        print("\n[ERROR] Digest must be exactly 64 hexadecimal characters.")
        return

    try:
        bytes.fromhex(target)
    except ValueError:
        print("\n[ERROR] Invalid hexadecimal digest.")
        return

    config = {
        "name": CHALLENGE2["name"],
        "target": target,
        "KEY_SBOX": CHALLENGE2["KEY_SBOX"],
        "PBOX": CHALLENGE2["PBOX"],
        "has_padding": CHALLENGE2["has_padding"]
    }

    recovered = solve(config)

    if recovered:
        print("\n[SUCCESS] Recovered plaintext:")
        print(recovered)
    else:
        print("\n[INFO] No printable plaintext recovered.")


if __name__ == "__main__":
    main()
