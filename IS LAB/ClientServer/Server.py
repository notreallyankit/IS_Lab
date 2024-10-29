# server.py
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


def start_server():
    # Generate server keys
    private_key, public_key = generate_keys()
    server_private_key = RSA.import_key(private_key)

    # Set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connected to client: {addr}")

            # Send server's public key to client
            client_socket.send(public_key)

            # Receive client's public key
            client_public_key_data = client_socket.recv(2048)
            client_public_key = RSA.import_key(client_public_key_data)

            # Receive encrypted message, signature, and hash
            encrypted_message = client_socket.recv(2048)
            signature = client_socket.recv(256)
            received_hash = client_socket.recv(256)

            # Decrypt message
            cipher = PKCS1_OAEP.new(server_private_key)
            decrypted_message = cipher.decrypt(encrypted_message)

            # Verify hash
            calculated_hash = SHA256.new(decrypted_message).digest()
            if calculated_hash != received_hash:
                print("Warning: Message integrity check failed!")
                continue

            # Verify signature
            try:
                hash_obj = SHA256.new(decrypted_message)
                pkcs1_15.new(client_public_key).verify(hash_obj, signature)
                print("Signature verification successful!")
                print(f"Received message: {decrypted_message.decode()}")

                # Send acknowledgment
                ack_message = "Message received and verified successfully!"
                ack_hash = SHA256.new(ack_message.encode())
                ack_signature = pkcs1_15.new(server_private_key).sign(ack_hash)

                cipher = PKCS1_OAEP.new(client_public_key)
                encrypted_ack = cipher.encrypt(ack_message.encode())

                client_socket.send(encrypted_ack)
                client_socket.send(ack_signature)

            except (ValueError, TypeError) as e:
                print(f"Warning: Signature verification failed! {e}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_socket.close()


if __name__ == '__main__':
    start_server()