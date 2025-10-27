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
from docx import Document as DocxLoader
from docx.document import Document as DocxDocument
from docx.oxml.table import CT_Tbl
from docx.oxml.text.paragraph import CT_P
from docx.table import _Cell, Table
from docx.text.paragraph import Paragraph


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
    preview_path: Optional[Path] = None
    preview_error: Optional[str] = None


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
    preview_path, preview_error = _generate_docx_preview(target_doc_path, base_dir, docx_path.stem)

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
        preview_path=preview_path,
        preview_error=preview_error,
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


def _generate_docx_preview(docx_path: Path, base_dir: Path, stem: str) -> Tuple[Optional[Path], Optional[str]]:
    """
    Create an HTML rendition of the DOCX contents for in-browser previewing.
    """
    try:
        document = DocxLoader(docx_path)
    except Exception:
        return None, "Preview unavailable for this document."

    try:
        html = _render_document_html(document)
    except Exception:
        return None, "Preview unavailable due to unsupported formatting."

    preview_path = base_dir / f"{stem}_preview.html"
    preview_path.write_text(html, encoding="utf-8")
    return preview_path, None


def _render_document_html(document: DocxDocument) -> str:
    """
    Convert a python-docx Document into a simplified, self-contained HTML page.
    """
    parts: List[str] = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<style>",
        "body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 1.5rem; color: #111827; background: #ffffff; }",
        "h1, h2, h3, h4, h5, h6 { color: #111827; margin: 1rem 0 0.5rem; }",
        "p { margin: 0 0 0.75rem; line-height: 1.6; }",
        "ul, ol { margin: 0 0 0.75rem 1.5rem; padding: 0; }",
        "li { margin: 0.35rem 0; }",
        "table { border-collapse: collapse; width: 100%; margin: 1rem 0; }",
        "td, th { border: 1px solid #d4d4d8; padding: 0.6rem; vertical-align: top; }",
        "th { background: #f4f4f5; font-weight: 600; }",
        ".doc-preview-body { max-width: 900px; margin: 0 auto; }",
        "</style>",
        "</head>",
        "<body class=\"doc-preview-body\">",
    ]

    open_list: Optional[str] = None

    for block in _iter_block_items(document):
        if isinstance(block, Paragraph):
            list_kind = _paragraph_list_kind(block)
            if list_kind:
                if open_list != list_kind:
                    if open_list:
                        parts.append(f"</{open_list}>")
                    parts.append(f"<{list_kind}>")
                    open_list = list_kind
                list_item = _render_runs_html(block)
                if list_item:
                    parts.append(f"<li>{list_item}</li>")
                continue
            if open_list:
                parts.append(f"</{open_list}>")
                open_list = None
            paragraph_html = _render_paragraph_html(block)
            if paragraph_html:
                parts.append(paragraph_html)
        elif isinstance(block, Table):
            if open_list:
                parts.append(f"</{open_list}>")
                open_list = None
            parts.append(_render_table_html(block))

    if open_list:
        parts.append(f"</{open_list}>")

    parts.extend(["</body>", "</html>"])
    return "\n".join(parts)


def _iter_block_items(parent):
    """
    Yield paragraphs and tables in document order, even when nested inside tables.
    """
    if isinstance(parent, DocxDocument):
        parent_element = parent.element.body
    elif isinstance(parent, _Cell):
        parent_element = parent._tc
    else:
        return

    for child in parent_element.iterchildren():
        if isinstance(child, CT_P):
            yield Paragraph(child, parent)
        elif isinstance(child, CT_Tbl):
            yield Table(child, parent)


def _paragraph_list_kind(paragraph: Paragraph) -> Optional[str]:
    style_name = (paragraph.style.name or "").lower() if paragraph.style else ""
    if style_name.startswith("list bullet"):
        return "ul"
    if style_name.startswith("list number"):
        return "ol"
    return None


def _render_paragraph_html(paragraph: Paragraph) -> str:
    run_html = _render_runs_html(paragraph)
    if not run_html:
        return ""

    style_name = paragraph.style.name if paragraph.style else ""
    tag = _heading_tag_for_style(style_name)
    if tag:
        return f"<{tag}>{run_html}</{tag}>"

    return f"<p>{run_html}</p>"


def _heading_tag_for_style(style_name: str) -> Optional[str]:
    heading_map = {
        "Heading 1": "h1",
        "Heading 2": "h2",
        "Heading 3": "h3",
        "Heading 4": "h4",
        "Heading 5": "h5",
        "Heading 6": "h6",
        "Title": "h1",
        "Subtitle": "h2",
    }
    return heading_map.get(style_name)


def _render_runs_html(paragraph: Paragraph) -> str:
    fragments: List[str] = []
    for run in paragraph.runs:
        if not run.text:
            continue
        text = escape(run.text).replace("\n", "<br>")
        if run.bold:
            text = f"<strong>{text}</strong>"
        if run.italic:
            text = f"<em>{text}</em>"
        if run.underline:
            text = f"<u>{text}</u>"
        fragments.append(text)
    return "".join(fragments).strip()


def _render_table_html(table: Table) -> str:
    rows_html: List[str] = []
    for row in table.rows:
        cells_html: List[str] = []
        for cell in row.cells:
            cell_fragments: List[str] = []
            for paragraph in cell.paragraphs:
                paragraph_html = _render_runs_html(paragraph)
                if paragraph_html:
                    cell_fragments.append(paragraph_html)
            cell_content = "<br>".join(cell_fragments) if cell_fragments else "&nbsp;"
            cells_html.append(f"<td>{cell_content}</td>")
        rows_html.append("<tr>" + "".join(cells_html) + "</tr>")
    return "<table class=\"doc-preview-table\">" + "".join(rows_html) + "</table>"
