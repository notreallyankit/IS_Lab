from dataclasses import dataclass
from typing import Dict, Optional
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


@dataclass
class PatientRecord:
    name: str
    symptoms: str
    diagnosis: str
    treatment: str


@dataclass
class User:
    id: str
    role: str  # 'doctor' or 'nurse'
    private_key: RSA.RsaKey
    public_key: RSA.RsaKey


class HealthcareSystem:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.patient_records: Dict[str, tuple[bytes, bytes, bytes]] = {}  # Encrypted records

    def generate_user_keys(self) -> tuple[RSA.RsaKey, RSA.RsaKey]:
        """Generate a new RSA key pair"""
        key = RSA.generate(2048)
        return key, key.publickey()

    def calculate_hash(self, data: str) -> bytes:
        """Calculate SHA-256 hash of the data"""
        hasher = SHA256.new()
        hasher.update(data.encode())
        return hasher.digest()

    def add_user(self, user_id: str, role: str) -> None:
        """Add a new user with generated RSA keys"""
        private_key, public_key = self.generate_user_keys()
        self.users[user_id] = User(user_id, role, private_key, public_key)
        print(f"Added {role}: {user_id}")

    def encrypt_data(self, data: str, recipient_public_key: RSA.RsaKey) -> tuple[bytes, bytes, bytes]:
        """Encrypt data using hybrid RSA/AES encryption"""
        # Generate AES key
        aes_key = get_random_bytes(32)  # 256-bit key

        # Create cipher for RSA encryption of the AES key
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key, hashAlgo=SHA256)

        # Encrypt the AES key with RSA
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Calculate hash of the data
        data_hash = self.calculate_hash(data)

        # Combine data and hash
        combined_data = data.encode() + data_hash

        # Generate random IV and create AES cipher
        iv = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        # Pad and encrypt the data
        padded_data = pad(combined_data, AES.block_size)
        ciphertext = cipher_aes.encrypt(padded_data)

        return encrypted_aes_key, iv, ciphertext

    def decrypt_data(self,
                     encrypted_data: tuple[bytes, bytes, bytes],
                     recipient_private_key: RSA.RsaKey) -> str:
        """Decrypt data using recipient's private key"""
        encrypted_aes_key, iv, ciphertext = encrypted_data

        # Create cipher for RSA decryption
        cipher_rsa = PKCS1_OAEP.new(recipient_private_key, hashAlgo=SHA256)

        try:
            # Decrypt the AES key
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            # Create AES cipher for decryption
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

            # Decrypt and unpad the data
            padded_data = cipher_aes.decrypt(ciphertext)
            combined_data = unpad(padded_data, AES.block_size)

            # Separate data and hash
            original_data = combined_data[:-32]  # SHA-256 hash is 32 bytes
            received_hash = combined_data[-32:]

            # Verify hash
            calculated_hash = self.calculate_hash(original_data.decode())
            if not calculated_hash == received_hash:
                raise ValueError("Data integrity check failed")

            return original_data.decode()

        except (ValueError, KeyError) as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def add_patient_record(self, doctor_id: str, record: PatientRecord) -> None:
        """Add an encrypted patient record"""
        if doctor_id not in self.users or self.users[doctor_id].role != 'doctor':
            raise ValueError("Only doctors can add patient records")

        # Encrypt the sensitive part of the record
        sensitive_data = json.dumps({
            'symptoms': record.symptoms,
            'diagnosis': record.diagnosis,
            'treatment': record.treatment
        })

        # Get doctor's public key
        doctor_public_key = self.users[doctor_id].public_key

        # Encrypt the sensitive data
        encrypted_data = self.encrypt_data(sensitive_data, doctor_public_key)

        # Store the record with plain name and encrypted sensitive data
        self.patient_records[record.name] = encrypted_data
        print(f"Added record for patient: {record.name}")

    def view_patient_record(self, user_id: str, patient_name: str) -> Optional[PatientRecord]:
        """View patient record based on user role"""
        if user_id not in self.users:
            raise ValueError("Invalid user")

        if patient_name not in self.patient_records:
            raise ValueError("Patient not found")

        user = self.users[user_id]
        encrypted_data = self.patient_records[patient_name]

        if user.role == 'nurse':
            # Nurses can only see patient name
            return PatientRecord(name=patient_name, symptoms="[RESTRICTED]",
                                 diagnosis="[RESTRICTED]", treatment="[RESTRICTED]")

        elif user.role == 'doctor':
            # Doctors can see everything
            try:
                sensitive_data = self.decrypt_data(encrypted_data, user.private_key)
                data = json.loads(sensitive_data)
                return PatientRecord(
                    name=patient_name,
                    symptoms=data['symptoms'],
                    diagnosis=data['diagnosis'],
                    treatment=data['treatment']
                )
            except ValueError as e:
                print(f"Error viewing record: {str(e)}")
                return None


def main():
    try:
        # Initialize the system
        health_system = HealthcareSystem()

        # Add users
        health_system.add_user("dr_smith", "doctor")
        health_system.add_user("nurse_jones", "nurse")

        # Add a patient record
        record = PatientRecord(
            name="John Doe",
            symptoms="High fever, cough",
            diagnosis="Influenza A",
            treatment="Oseltamivir 75mg twice daily"
        )

        # Doctor adds patient record
        health_system.add_patient_record("dr_smith", record)

        # View record as doctor
        doctor_view = health_system.view_patient_record("dr_smith", "John Doe")
        if doctor_view:
            print("\nDoctor's view of patient record:")
            print(f"Name: {doctor_view.name}")
            print(f"Symptoms: {doctor_view.symptoms}")
            print(f"Diagnosis: {doctor_view.diagnosis}")
            print(f"Treatment: {doctor_view.treatment}")

        # View record as nurse
        nurse_view = health_system.view_patient_record("nurse_jones", "John Doe")
        if nurse_view:
            print("\nNurse's view of patient record:")
            print(f"Name: {nurse_view.name}")
            print(f"Symptoms: {nurse_view.symptoms}")
            print(f"Diagnosis: {nurse_view.diagnosis}")
            print(f"Treatment: {nurse_view.treatment}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()