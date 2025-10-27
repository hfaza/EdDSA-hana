import tempfile
from pathlib import Path
from typing import Dict, Optional

from django.conf import settings
from django.shortcuts import render

from .forms import DocumentSignForm, DocumentVerifyForm
from .utils import (
    SignatureBundle,
    UnsupportedDocumentError,
    VerificationReport,
    build_signature_bundle,
    verify_document,
)


def _relative_media_url(path: Path) -> str:
    return settings.MEDIA_URL + path.relative_to(settings.MEDIA_ROOT).as_posix()


def home(request):
    sign_form = DocumentSignForm(request.POST or None, request.FILES or None, prefix="sign")
    verify_form = DocumentVerifyForm(request.POST or None, request.FILES or None, prefix="verify")

    sign_result: Optional[SignatureBundle] = None
    sign_error: Optional[str] = None
    verify_result: Optional[str] = None
    verify_report: Optional[VerificationReport] = None
    verify_error: Optional[str] = None

    if request.method == "POST":
        if "sign-submit" in request.POST and sign_form.is_valid():
            uploaded_file = sign_form.cleaned_data["document"]
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as temp_file:
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)
                temp_path = Path(temp_file.name)
            try:
                sign_result = build_signature_bundle(temp_path)
            except UnsupportedDocumentError as exc:
                sign_error = str(exc)
            finally:
                temp_path.unlink(missing_ok=True)
        elif "verify-submit" in request.POST and verify_form.is_valid():
            doc_file = verify_form.cleaned_data["document"]
            sig_file = verify_form.cleaned_data["signature"]
            pub_file = verify_form.cleaned_data["public_key"]
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_dir_path = Path(tmp_dir)
                doc_path = tmp_dir_path / doc_file.name
                sig_path = tmp_dir_path / sig_file.name
                pub_path = tmp_dir_path / pub_file.name
                for src, dest in (
                    (doc_file, doc_path),
                    (sig_file, sig_path),
                    (pub_file, pub_path),
                ):
                    with dest.open("wb") as fh:
                        for chunk in src.chunks():
                            fh.write(chunk)
                try:
                    verify_report = verify_document(doc_path, sig_path, pub_path)
                    if verify_report.is_valid:
                        verify_result = "Signature matches — the document is authentic."
                    else:
                        verify_result = "Signature mismatch — the document or signature appears to be altered."
                except UnsupportedDocumentError as exc:
                    verify_error = str(exc)

    media_links: Optional[Dict[str, str]] = None
    if sign_result:
        media_links = {
            "document": _relative_media_url(sign_result.document_path),
            "signature": _relative_media_url(sign_result.signature_path),
            "public_key": _relative_media_url(sign_result.public_key_path),
            "digest": _relative_media_url(sign_result.digest_path),
        }
        if sign_result.preview_path:
            media_links["preview"] = _relative_media_url(sign_result.preview_path)

    context = {
        "sign_form": sign_form,
        "verify_form": verify_form,
        "sign_result": sign_result,
        "sign_error": sign_error,
        "verify_result": verify_result,
        "verify_report": verify_report,
        "verify_error": verify_error,
        "media_links": media_links,
    }
    return render(request, "signer/home.html", context)
