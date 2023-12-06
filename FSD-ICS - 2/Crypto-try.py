from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def generate_key():
    # Generate a random key
    return get_random_bytes(32)

def encrypt(text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return b64encode(encrypted_text).decode('utf-8')

def decrypt(encrypted_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(b64decode(encrypted_text)), AES.block_size)
    return decrypted_text.decode('utf-8')

# Example usage
generated_key = b'3bmzBA+g8S9pXq/xRtk3fQ=='
print(f'Generated Key: {b64encode(generated_key).decode("utf-8")}')

plain_text = "Hello, AES!"
encrypted_text = encrypt(plain_text, generated_key)
decrypted_text = decrypt(encrypted_text, generated_key)

print(f'Original Text: {plain_text}')
print(f'Encrypted Text: {encrypted_text}')
print(f'Decrypted Text: {decrypted_text}')
