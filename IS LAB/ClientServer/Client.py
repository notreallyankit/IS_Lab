# client.py
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


def generate_keys():
    """Generate a new pair of RSA keys"""
    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def send_secure_message(message):
    # Generate client keys
    client_private_key, client_public_key = generate_keys()

    # Set up client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    try:
        # Receive server's public key
        server_public_key_data = client_socket.recv(2048)
        server_public_key = RSA.import_key(server_public_key_data)

        # Send client's public key
        client_socket.send(client_public_key)

        # Convert message to bytes
        message_bytes = message.encode()

        # Create hash of original message
        message_hash = SHA256.new(message_bytes).digest()

        # Create digital signature
        hash_obj = SHA256.new(message_bytes)
        signature = pkcs1_15.new(RSA.import_key(client_private_key)).sign(hash_obj)

        # Encrypt message
        cipher = PKCS1_OAEP.new(server_public_key)
        encrypted_message = cipher.encrypt(message_bytes)

        # Send encrypted message, signature, and hash
        client_socket.send(encrypted_message)
        client_socket.send(signature)
        client_socket.send(message_hash)

        print("Signed message sent securely!")

        # Receive server acknowledgment
        encrypted_ack = client_socket.recv(2048)
        ack_signature = client_socket.recv(256)

        # Decrypt acknowledgment
        cipher = PKCS1_OAEP.new(RSA.import_key(client_private_key))
        decrypted_ack = cipher.decrypt(encrypted_ack)

        # Verify server's signature
        try:
            ack_hash = SHA256.new(decrypted_ack)
            pkcs1_15.new(server_public_key).verify(ack_hash, ack_signature)
            print(f"Server response verified: {decrypted_ack.decode()}")
        except (ValueError, TypeError) as e:
            print(f"Warning: Server acknowledgment signature verification failed! {e}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


if __name__ == '__main__':
    message = input("Enter message to send: ")
    send_secure_message(message)