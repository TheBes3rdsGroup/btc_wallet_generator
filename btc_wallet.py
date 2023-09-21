import os
import hashlib
import ecdsa
import base58

def generate_private_key():
    # Generate a random 256-bit (32-byte) private key
    private_key_bytes = os.urandom(32)
    private_key_hex = private_key_bytes.hex()
    return private_key_hex

def calculate_public_key(private_key):
    # Convert the private key to bytes
    private_key_bytes = bytes.fromhex(private_key)
    
    # Use ecdsa to calculate the public key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    public_key_bytes = verifying_key.to_string("compressed")
    public_key_hex = public_key_bytes.hex()
    
    return public_key_hex

def calculate_address(public_key):
    # Hash the public key
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Add a network byte (0x00 for Bitcoin mainnet)
    network_byte = b'\x00'
    extended_ripemd160_hash = network_byte + ripemd160_hash
    
    # Calculate the checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160_hash).digest()).digest()[:4]
    
    # Combine the extended RIPEMD160 hash and checksum
    binary_address = extended_ripemd160_hash + checksum
    
    # Encode the binary address to base58
    address = base58.b58encode(binary_address)
    
    return address.decode('utf-8')

if __name__ == '__main__':
    # Generate a random private key
    private_key = generate_private_key()
    
    # Calculate the public key and Bitcoin address
    public_key = calculate_public_key(private_key)
    address = calculate_address(public_key)
    
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    print("Bitcoin Address:", address)
