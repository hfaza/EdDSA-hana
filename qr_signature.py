import json
import os
from datetime import datetime, timedelta
import uuid

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend


def generate_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """
    Generates an Ed25519 private and public key pair and saves them to PEM files.
    """
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("Keys already exist. Skipping key generation.")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return private_key, public_key

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"Keys generated and saved to {private_key_path} and {public_key_path}")
    return private_key, public_key


def generate_qr_code_signature(
    data: dict,
    private_key: ed25519.Ed25519PrivateKey,
    qr_code_filename: str = "qrcode.png",
    expiration_days: int = 7
):
    """
    Generates a QR code with a digital signature for the given data using Ed25519.

    Args:
        data (dict): The data to be signed and encoded in the QR code.
                     Expected to contain 'customer_id', 'discount_value',
                     'discount_type'.
        private_key (ed25519.Ed25519PrivateKey): The Ed25519 private key for signing.
        qr_code_filename (str): The filename for the generated QR code image.
        expiration_days (int): Number of days until the QR code expires.

    Returns:
        str: The path to the generated QR code image.
    """
    # Add unique ID and expiration to the data
    qr_id = str(uuid.uuid4())
    expiration_date = (datetime.now() + timedelta(days=expiration_days)).isoformat()
    
    payload = {
        "qr_id": qr_id,
        "expiration_date": expiration_date,
        **data
    }

    # Serialize payload to JSON string for signing
    payload_str = json.dumps(payload, sort_keys=True)
    payload_bytes = payload_str.encode("utf-8")

    # Sign the payload
    signature = private_key.sign(payload_bytes)

    # Combine payload and signature for QR code
    qr_data = {
        "payload": payload,
        "signature": signature.hex()  # Convert signature to hex string for easy encoding
    }
    qr_data_str = json.dumps(qr_data)

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data_str)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(qr_code_filename)

    return qr_code_filename


def verify_qr_code_signature(qr_data_str: str, public_key: ed25519.Ed25519PublicKey) -> bool:
    """
    Verifies the digital signature embedded in QR code data using Ed25519.

    Args:
        qr_data_str (str): The JSON string read from the QR code.
        public_key (ed25519.Ed25519PublicKey): The Ed25519 public key for verification.

    Returns:
        bool: True if the signature is valid and data has not expired, False otherwise.
    """
    try:
        qr_data = json.loads(qr_data_str)
        payload = qr_data["payload"]
        signature_hex = qr_data["signature"]
        signature = bytes.fromhex(signature_hex)

        payload_str = json.dumps(payload, sort_keys=True)
        payload_bytes = payload_str.encode("utf-8")

        # Verify the signature
        public_key.verify(signature, payload_bytes)
        
        # Check expiration date
        expiration_date_str = payload.get("expiration_date")
        if expiration_date_str:
            expiration_date = datetime.fromisoformat(expiration_date_str)
            if datetime.now() > expiration_date:
                print("QR code has expired.")
                return False

        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


if __name__ == "__main__":
    # Example Usage
    private_key, public_key = generate_keys("projects/EdDSA-hana/private_key.pem", "projects/EdDSA-hana/public_key.pem")

    # Data for the QR code
    discount_data = {
        "customer_id": "user123",
        "discount_value": 10.50,
        "discount_type": "percentage"
    }

    # Generate QR code with signature
    qr_filename = generate_qr_code_signature(
        data=discount_data,
        private_key=private_key,
        qr_code_filename="projects/EdDSA-hana/signed_discount_qr.png",
        expiration_days=30
    )
    print(f"Generated signed QR code: {qr_filename}")

    # To verify, you would typically read the QR code and get its string content
    # For demonstration, let's simulate reading the content
    # In a real scenario, you'd scan the QR code and extract qr_data_str
    
    # We need to simulate reading the QR code content.
    # To do this, we'll need to use the qrcode library to read the data from the generated image.
    # However, the qrcode library itself does not have a built-in function to read QR codes from images.
    # This usually requires a separate library like `pylibdmtx`, `zbarlight`, or `opencv`.
    # For simplicity and to avoid adding more dependencies, I'll directly use the `qr_data_str`
    # that was used to generate the QR code for verification.

    # This is the actual string that would be encoded in the QR code
    # We will reconstruct it for the verification step
    qr_id_example = str(uuid.uuid4()) # Placeholder, as actual ID is generated inside
    expiration_date_example = (datetime.now() + timedelta(days=30)).isoformat()
    
    # Recreate the payload as it would be in the QR code
    example_payload = {
        "qr_id": qr_id_example,
        "expiration_date": expiration_date_example,
        **discount_data
    }

    # Simulate signing again to get the signature for the example qr_data_str
    example_payload_str = json.dumps(example_payload, sort_keys=True)
    example_payload_bytes = example_payload_str.encode("utf-8")

    example_signature = private_key.sign(example_payload_bytes)

    example_qr_data = {
        "payload": example_payload,
        "signature": example_signature.hex()
    }
    simulated_qr_data_str = json.dumps(example_qr_data)


    # Verify the QR code signature
    is_valid = verify_qr_code_signature(simulated_qr_data_str, public_key)
    print(f"QR code signature is valid: {is_valid}")

    # Test with tampered data (for demonstration)
    print("\nTesting with tampered data...")
    tampered_payload = {**discount_data, "discount_value": 5.00}
    tampered_payload["qr_id"] = qr_id_example # Keep same QR ID
    tampered_payload["expiration_date"] = expiration_date_example # Keep same expiration
    
    tampered_qr_data = {
        "payload": tampered_payload,
        "signature": example_signature.hex() # Use original signature
    }
    tampered_qr_data_str = json.dumps(tampered_qr_data)
    
    is_tampered_valid = verify_qr_code_signature(tampered_qr_data_str, public_key)
    print(f"Tampered QR code signature is valid (should be False): {is_tampered_valid}")
    
    # Test with expired data (for demonstration)
    print("\nTesting with expired data...")
    expired_payload = {
        "qr_id": str(uuid.uuid4()),
        "expiration_date": (datetime.now() - timedelta(days=1)).isoformat(), # Yesterday
        **discount_data
    }
    expired_payload_str = json.dumps(expired_payload, sort_keys=True)
    expired_payload_bytes = expired_payload_str.encode("utf-8")
    expired_signature = private_key.sign(expired_payload_bytes)
    expired_qr_data = {
        "payload": expired_payload,
        "signature": expired_signature.hex()
    }
    expired_qr_data_str = json.dumps(expired_qr_data)
    
    is_expired_valid = verify_qr_code_signature(expired_qr_data_str, public_key)
    print(f"Expired QR code signature is valid (should be False): {is_expired_valid}")
