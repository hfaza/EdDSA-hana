import hashlib
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
import shutil
from html import escape
from typing import List, Optional, Tuple

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
    signature_path: Path
    public_key_path: Path
    digest_path: Path
    digest_hex: str


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

    signature_path = base_dir / f"{docx_path.stem}.sig"
    signature_path.write_bytes(signature)

    public_key_path = base_dir / f"{docx_path.stem}_public.pem"
    public_key_path.write_bytes(public_key)

    digest_path = base_dir / f"{docx_path.stem}_digest.txt"
    digest_path.write_text(digest.hex())

    return SignatureBundle(
        session_id=session_id,
        document_path=target_doc_path,
        signature_path=signature_path,
        public_key_path=public_key_path,
        digest_path=digest_path,
        digest_hex=digest.hex(),
    )


def verify_document(docx_path: Path, signature_path: Path, public_key_path: Path) -> VerificationReport:
    digest = compute_document_hash(docx_path)
    digest_hex = digest.hex()
    signature = signature_path.read_bytes()
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    try:
        public_key.verify(signature, digest)
        return VerificationReport(is_valid=True, digest_hex=digest_hex)
    except InvalidSignature:
        return VerificationReport(is_valid=False, digest_hex=digest_hex)



