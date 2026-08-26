from gmpy2 import mpz


def clean_hex(value):
    return (
        value
        .replace(":", "")
        .replace(" ", "")
        .strip()
        .lower()
    )


def read_hex(name):
    value = input(f"Enter '{name}' Hex: ")
    clean = clean_hex(value)

    if clean.startswith("0x"):
        clean = clean[2:]

    if not clean:
        raise ValueError(f"{name} is empty.")

    try:
        int(clean, 16)
    except ValueError:
        raise ValueError(
            f"{name} contains invalid hexadecimal characters."
        )

    return clean


try:
    # DH parameters
    p_hex = read_hex("p")
    g_hex = read_hex("g")

    # TLS/application nonces
    client_nonce = read_hex("Client Nonce")
    server_nonce = read_hex("Server Nonce")

    # Convert p/g to large integers
    gmp_p = mpz(int(p_hex, 16))
    gmp_g = mpz(int(g_hex, 16))

    print("\n" + "=" * 60)
    print("[SUCCESS] Cryptographic Parameters Parsed")
    print("=" * 60)

    print(f"p (decimal)       : {gmp_p}")
    print(f"g (decimal)       : {gmp_g}")

    print(f"\nClient Nonce (hex): {client_nonce}")
    print(f"Server Nonce (hex): {server_nonce}")

    print("=" * 60)

except ValueError as e:
    print(f"\n[ERROR] {e}")
