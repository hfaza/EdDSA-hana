import hashlib
import uuid
import zipfile
import json
from dataclasses import dataclass
from pathlib import Path
import shutil
from html import escape
from typing import List, Optional, Tuple

import cv2
import numpy as np
import qrcode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings


class UnsupportedDocumentError(Exception):
    """Raised when the uploaded document is not compatible with the signer."""


@dataclass
class SignatureBundle:
    session_id: str
    document_path: Path
    public_key_path: Path
    digest_path: Path
    digest_hex: str
    qr_path: Path


@dataclass
class VerificationReport:
    is_valid: bool
    digest_hex: str


def _session_dir(session_id: Optional[str] = None) -> Tuple[str, Path]:
    session_id = session_id or uuid.uuid4().hex[:16]
    base_dir = Path(settings.MEDIA_ROOT) / "sessions" / session_id
    base_dir.mkdir(parents=True, exist_ok=True)
    return session_id, base_dir


def _read_document_xml(docx_path: Path) -> bytes:
    try:
        with zipfile.ZipFile(docx_path, "r") as archive:
            return archive.read("word/document.xml")
    except KeyError as exc:  # missing XML
        raise UnsupportedDocumentError("DOCX file is missing word/document.xml") from exc
    except zipfile.BadZipFile as exc:
        raise UnsupportedDocumentError("Uploaded file is not a valid DOCX archive") from exc


def compute_document_hash(docx_path: Path) -> bytes:
    xml_bytes = _read_document_xml(docx_path)
    return hashlib.sha256(xml_bytes).digest()


def build_signature_bundle(docx_path: Path) -> SignatureBundle:
    session_id, base_dir = _session_dir()
    target_doc_path = base_dir / docx_path.name
    shutil.copy2(docx_path, target_doc_path)

    digest = compute_document_hash(target_doc_path)

    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(digest)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_key_path = base_dir / f"{docx_path.stem}_public.pem"
    public_key_path.write_bytes(public_key)

    digest_path = base_dir / f"{docx_path.stem}_digest.txt"
    digest_path.write_text(digest.hex())

    # Generate QR Code
    qr_data = {
        "digest": digest.hex(),
        "signature": signature.hex(),
        "algorithm": "Ed25519"
    }
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(json.dumps(qr_data))
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_path = base_dir / f"{docx_path.stem}_signature.png"
    qr_img.save(qr_path)

    return SignatureBundle(
        session_id=session_id,
        document_path=target_doc_path,
        public_key_path=public_key_path,
        digest_path=digest_path,
        digest_hex=digest.hex(),
        qr_path=qr_path,
    )


def _extract_signature_from_qr(qr_path: Path) -> bytes:
    try:
        img = cv2.imread(str(qr_path))
        if img is None:
            raise UnsupportedDocumentError("Could not read the signature QR code image.")
        
        detector = cv2.QRCodeDetector()
        
        # 1. Try with original image
        data, points, _ = detector.detectAndDecode(img)
        
        # 2. Try with grayscale
        if not data:
            gray_img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            data, points, _ = detector.detectAndDecode(gray_img)
            
        # 3. Try with binary thresholding
        if not data:
            gray_img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh_img = cv2.threshold(gray_img, 128, 255, cv2.THRESH_BINARY)
            data, points, _ = detector.detectAndDecode(thresh_img)

        # 4. Try with adaptive thresholding
        if not data:
            gray_img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            thresh_img = cv2.adaptiveThreshold(gray_img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
            data, points, _ = detector.detectAndDecode(thresh_img)

        if not data:
            raise UnsupportedDocumentError("No QR code detected in the image.")
            
        payload = json.loads(data)
        signature_hex = payload.get("signature")
        if not signature_hex:
            raise UnsupportedDocumentError("QR code does not contain a signature.")
            
        return bytes.fromhex(signature_hex)
    except json.JSONDecodeError:
        raise UnsupportedDocumentError("QR code content is not valid JSON.")
    except ValueError:
        raise UnsupportedDocumentError("Invalid hex signature in QR code.")
    except Exception as e:
        if isinstance(e, UnsupportedDocumentError):
            raise e
        raise UnsupportedDocumentError(f"Failed to process QR code: {e}")


def verify_document(docx_path: Path, signature_path: Path, public_key_path: Path) -> VerificationReport:
    digest = compute_document_hash(docx_path)
    digest_hex = digest.hex()
    
    if signature_path.suffix.lower() == '.png':
        signature = _extract_signature_from_qr(signature_path)
    else:
        signature = signature_path.read_bytes()
        
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    try:
        public_key.verify(signature, digest)
        return VerificationReport(is_valid=True, digest_hex=digest_hex)
    except InvalidSignature:
        return VerificationReport(is_valid=False, digest_hex=digest_hex)



