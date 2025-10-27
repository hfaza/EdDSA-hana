# EdDSA Signer – Full Walkthrough for Students

This document teaches how the Django-based EdDSA signer works and how you could recreate the project from scratch. It highlights important considerations so learners can both understand the current implementation and present the system confidently.

---

## 1. What the App Does

1. Accept a Microsoft Word DOCX file.
2. Compute a SHA-256 digest of `word/document.xml`.
3. Generate a fresh Ed25519 key pair and sign the digest.
4. Save a bundle containing the document copy, `.sig`, public key, digest, and an HTML preview.
5. Display the digest and a live browser preview so reviewers can read the document before sharing the bundle.

> **Key Idea:** The signature is attached to the XML contents inside the DOCX archive, so accidental formatting differences (like zipped metadata) do not break verification.

---

## 2. Setting Up the Project

1. **Create the Django project and app**
   ```bash
   django-admin startproject eddsa_site
   cd eddsa_site
   python3 manage.py startapp signer
   ```
2. **Install dependencies** (`requirements.txt`)
   ```text
   Django>=4.2,<4.3
   cryptography>=41.0
   python-docx>=0.8.11
   django-browser-reload>=1.12
   ```
3. **Virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
4. **Project structure essentials**
   ```
   eddsa_site/
     manage.py
     eddsa_site/settings.py
     eddsa_site/urls.py
     signer/
       views.py
       forms.py
       utils.py
       urls.py
       templates/signer/home.html
       static/signer/css/styles.css
   media/  # generated at runtime
   docs/document-preview-guide.md
   ```

---

## 3. Django Configuration

- `edddsa_site/settings.py`
  - `INSTALLED_APPS` includes `signer` and `django_browser_reload`.
  - `MEDIA_ROOT`/`MEDIA_URL` point to `media/`.
  - `STATICFILES_DIRS` includes the project-level `static/`.
  - `X_FRAME_OPTIONS = "SAMEORIGIN"` so the preview HTML can load inside an iframe while still defending against clickjacking on other hosts.

> **Important:** Always restart the development server after changing security-related settings; otherwise the iframe may keep showing “refused to connect.”

- `eddsa_site/urls.py`
  ```python
  urlpatterns = [
      path("admin/", admin.site.urls),
      path("", include("signer.urls")),
  ]
  if settings.DEBUG:
      urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
  ```
  Serving media in `DEBUG` mode is sufficient for local labs.

---

## 4. Forms and User Input

- `signer/forms.py`
  ```python
  class DocumentSignForm(forms.Form):
      document = forms.FileField(label="DOCX to sign")
  ```
  The form is minimal—Django handles file upload parsing and validation automatically.

- `signer/templates/signer/home.html`
  - Contains two `<form>` blocks (sign and verify) distinguished by button names.
  - Uses `{{ sign_form.as_p }}` to render the file input with label wiring intact.
  - Submission triggers the `home` view (see below).

> **Tip for Learners:** When your form needs multiple file inputs, prefix each form (e.g., `prefix="sign"`) to keep field names unique.

---

## 5. The `home` View (Workflow Orchestration)

- Located in `signer/views.py`.
- Core logic:
  1. Instantiate both forms using `request.POST`/`request.FILES`.
  2. On sign submission:
     - Copy the uploaded DOCX to a temporary file.
     - Call `build_signature_bundle`.
     - Capture errors via `UnsupportedDocumentError`.
  3. On verify submission:
     - Copy uploaded files into a temporary directory.
     - Call `verify_document` to check the signature.
  4. Populate `media_links` using `_relative_media_url`.
  5. Render `signer/home.html` with context.

```python
if sign_result:
    media_links = {
        "document": _relative_media_url(sign_result.document_path),
        "signature": _relative_media_url(sign_result.signature_path),
        "public_key": _relative_media_url(sign_result.public_key_path),
        "digest": _relative_media_url(sign_result.digest_path),
    }
    if sign_result.preview_path:
        media_links["preview"] = _relative_media_url(sign_result.preview_path)
```

> **Important:** Always unlink temporary uploads after processing so they don’t linger in `/tmp`. This project uses `tempfile.NamedTemporaryFile` and `TemporaryDirectory` inside context managers for exactly that reason.

---

### 5.1 Deep Dive: How the `home` View Implements the Workflow

```python
def home(request):
    sign_form = DocumentSignForm(request.POST or None, request.FILES or None, prefix="sign")
    verify_form = DocumentVerifyForm(request.POST or None, request.FILES or None, prefix="verify")
    ...
    if request.method == "POST":
        if "sign-submit" in request.POST and sign_form.is_valid():
            uploaded_file = sign_form.cleaned_data["document"]
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as temp_file:
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)
            ...
```

1. **Form instantiation:** Both forms are created on every request. Using prefixes keeps `<input name="...">` attributes unique so Django can bind the right data to each form without collisions.
2. **Detecting the active form:** The template’s submit buttons include `name="sign-submit"` and `name="verify-submit"`. The view examines `request.POST` to pick the correct branch.
3. **Streaming uploads:** `uploaded_file.chunks()` prevents loading large documents into memory. The temporary file uses the original suffix so downstream helpers treat it like a real DOCX.
4. **Delegating to utilities:** The freshly written temp path is passed to `build_signature_bundle`. Even if that call raises an exception, the `finally` block (or `missing_ok=True`) ensures cleanup.
5. **Verification path mirror:** For verification, a `TemporaryDirectory` holds all uploaded artifacts, and each file is copied using the same chunked approach before calling `verify_document`.
6. **Context preparation:** `media_links` maps every generated artifact to a browser-accessible URL. Preview links are added only when the preview file exists.

> **Teaching Point:** Show students how Django’s form handling, temporary file management, and service-style utility functions keep the view slim and readable, even though the workflow is complex.

---

## 6. Signature Bundle Generation (`signer/utils.py`)

### `build_signature_bundle(docx_path: Path) -> SignatureBundle`

1. Create a session directory under `media/sessions/<uuid>/`.
2. Copy the DOCX into the session folder (preserving the original for later downloads).
3. Compute SHA-256 using `compute_document_hash`.
4. Generate an Ed25519 key pair with `cryptography.hazmat`.
5. Sign the digest and save the signature and public key files.
6. Write the digest hex representation to `<stem>_digest.txt`.
7. Call `_generate_docx_preview` (see next section).
8. Return `SignatureBundle` with file paths and digest.

> **Note:** The bundle uses randomly generated session IDs rather than user IDs to avoid leaking identity information when multiple people use the same machine.

### `compute_document_hash`

- Opens the DOCX as a ZIP archive.
- Reads `word/document.xml`.
- Returns `hashlib.sha256(xml_bytes).digest()`.
- The raw digest (bytes) is kept for signing; `digest.hex()` is written to disk for humans.

> **Cryptography Quick Recap:** The digest acts as the “message” Ed25519 signs. Hashing the XML keeps the signed payload deterministic, even if the DOCX package stores thumbnails or unzip order differently.

### Ed25519 Signature Logic (inside `build_signature_bundle`)

```python
private_key = Ed25519PrivateKey.generate()
signature = private_key.sign(digest)
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
```

- **Key generation:** `Ed25519PrivateKey.generate()` produces a random 32-byte private key (RFC 8032 compliant). A matching public key is derived with `private_key.public_key()`.
- **Signing:** `private_key.sign(digest)` returns a 64-byte Ed25519 signature.
- **Serialization:** The public key is converted to PEM so it can be shared and re-used by other tools. PEM is a base64 encoding with header/footer lines.
- **Outputs written:** 
  - `<stem>.sig` — raw binary signature.
  - `<stem>_public.pem` — PEM-encoded public key.
  - `<stem>_digest.txt` — lowercase hex of SHA-256 digest.

> **Important Concept to Teach:** Anyone with the `.sig`, `.pem`, and original DOCX can recompute the digest and call Ed25519 `verify` to confirm authenticity—no secret information is needed after the bundle is created.

> **Risk Highlight:** If `word/document.xml` is missing, `UnsupportedDocumentError` is raised. This catches renamed files that are not true DOCX archives and reduces misleading signatures.

### 6.1 Step-by-Step Through `build_signature_bundle`

```python
session_id, base_dir = _session_dir()
target_doc_path = base_dir / docx_path.name
shutil.copy2(docx_path, target_doc_path)
digest = compute_document_hash(target_doc_path)
preview_path, preview_error = _generate_docx_preview(target_doc_path, base_dir, docx_path.stem)
```

1. **Session folder creation:** `_session_dir` generates a short hexadecimal ID and ensures `media/sessions/<id>/` exists. This isolates artifacts from different signing runs.
2. **Copying the document:** `shutil.copy2` duplicates the original DOCX into the session folder. Using `copy2` (not `copy`) preserves metadata such as modification time.
3. **Hash computation:** `compute_document_hash` always runs on the copied file so the temp upload can be removed immediately.
4. **Preview generation:** `_generate_docx_preview` returns either a preview path or an error message that will be surfaced to the user.

After setup, cryptographic artifacts are created:

```python
private_key = Ed25519PrivateKey.generate()
signature = private_key.sign(digest)
public_key = private_key.public_key().public_bytes(...)
signature_path.write_bytes(signature)
public_key_path.write_bytes(public_key)
digest_path.write_text(digest.hex())
```

5. **Key & signature:** The Ed25519 private key signs the raw digest bytes; the signature is written as binary with no encoding to avoid bloat.
6. **Public key export:** The PEM-formatted public key is human-readable and interoperable with other tooling.
7. **Digest storage:** Saving the hex digest provides a quick fingerprint people can compare without custom software.

Finally, the `SignatureBundle` dataclass wraps the resulting artifacts:

```python
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
```

- Keeping absolute `Path` objects in the dataclass lets the view generate relative URLs while still having full filesystem access if additional processing is needed.

---

## 7. Rendering HTML Previews

### `_generate_docx_preview`

```python
preview_path = base_dir / f"{stem}_preview.html"
preview_path.write_text(html, encoding="utf-8")
```

- Loads the DOCX with `DocxLoader`.
- Delegates to `_render_document_html`.
- If anything fails, returns `(None, "Preview unavailable…")` so the UI can display a friendly message.

### `_render_document_html`

- Builds a complete HTML document string with embedded CSS.
- Iterates through paragraphs and tables using `_iter_block_items`.
- Handles list styles by inspecting `paragraph.style.name`.
- Uses `_render_runs_html` to wrap bold/italic/underline segments.
- Generates `<table>` markup for every Word table row/cell.

> **Security Note:** All text content is escaped with `html.escape` before being inserted into the HTML. This prevents malicious DOCX content from injecting scripts into the preview.

### `_iter_block_items`

- Emits paragraphs and tables in document order.
- Supports nested tables by recursing into `_Cell` elements.

### `_render_table_html`

- Ensures each cell shows a non-breaking space (`&nbsp;`) when empty so borders remain visible.
- Joins paragraphs inside a cell with `<br>` to prevent loss of multi-line content.

---

## 8. Front-End: Preview Card and Styling

- Template snippet (iframe render):
  ```html
  {% if media_links.preview %}
      <iframe
          class="doc-preview-frame"
          src="{{ media_links.preview }}"
          title="Signed document preview"
          loading="lazy"
      ></iframe>
      <p class="preview-note">
          Having trouble? <a href="{{ media_links.preview }}" target="_blank" rel="noopener">Open the preview in a new tab</a>.
      </p>
  {% elif sign_result.preview_error %}
      <p class="preview-note">{{ sign_result.preview_error }}</p>
  {% else %}
      <p class="preview-note">Preview unavailable.</p>
  {% endif %}
  ```

- Key CSS rules (`signer/static/signer/css/styles.css`):
  ```css
  .doc-preview-frame {
      width: 100%;
      min-height: 420px;
      border: 1px solid rgba(148, 163, 184, 0.35);
      border-radius: 10px;
      background: #ffffff;
  }
  .preview-note a {
      color: #1d4ed8;
      text-decoration: none;
      font-weight: 600;
  }
  ```

> **UI Reminder:** Encourage students to explain why the preview sits next to the download links—it lets reviewers inspect the document immediately before trusting the signature.

---

## 9. Verification Path (for completeness)

- `verify_document` (in `signer/utils.py`) reads the uploaded document, signature, and public key.
- Recomputes the SHA-256 digest the same way as during signing.
- Loads the public key with `serialization.load_pem_public_key`.
- Calls `public_key.verify(signature, digest)`.
  - If the signature matches, `is_valid=True`.
  - If a `InvalidSignature` exception is raised, the function returns `is_valid=False`.
- The verify card in the template shows success or mismatch messaging accordingly (`signer/templates/signer/home.html`).

> **Highlight for Students:** The verifier never needs the private key. The only secret is discarded after signing. This is the heart of asymmetric cryptography.

> **Key Learning:** Hashing the XML ensures that even if the DOCX’s media or metadata changes, the verification catches it. This is a powerful example when teaching integrity checks.

### 9.1 Implementation Breakdown

```python
digest = compute_document_hash(docx_path)
signature = signature_path.read_bytes()
public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
try:
    public_key.verify(signature, digest)
    return VerificationReport(is_valid=True, digest_hex=digest_hex)
except InvalidSignature:
    return VerificationReport(is_valid=False, digest_hex=digest_hex)
```

1. **Digest recomputation:** Uses the exact same helper as the signing flow, removing any chance of mismatched hashing algorithms.
2. **Loading artifacts:** The signature is raw bytes; the PEM loader returns an Ed25519 public key object ready for verification.
3. **Verification call:** `public_key.verify` throws an exception when the signature doesn’t match, allowing the function to map success/failure to a simple boolean.
4. **Digest reuse:** The hex digest is included in the `VerificationReport` regardless of outcome so the UI can display it for debugging or audit logs.

> **Troubleshooting Tip:** If verification fails, compare the displayed digest against the signer’s `*_digest.txt`. If they differ, the document contents have changed; if they match, it’s likely the wrong public key/signature pair.

---

## 10. Running & Demonstrating the App

1. `python3 manage.py migrate`
2. `python3 manage.py runserver`
3. Visit `http://127.0.0.1:8000`.
4. Upload a DOCX containing:
   - Title & headings
   - Bullet and numbered lists
   - A table with a few rows
5. Point out:
   - Digest line in the success message.
   - Download buttons.
   - Preview iframe and “open in new tab” link.
6. Download the `.sig` and `.pem` files, then use the verify form to demonstrate complete round-trip validation.

---

## 11. Extension Ideas for Students

- **Add authentication** so only approved users can sign documents.
- **Implement cleanup** to delete session folders after a certain age.
- **Display images** by copying embedded media to the preview directory and adjusting HTML.
- **API endpoints** for automated systems to request signatures.
- **Unit tests** covering `compute_document_hash`, preview generation, and signature verification with known test vectors.

> **Encouragement:** Each extension teaches a different layer of Django (auth, background jobs, file handling, REST APIs). Pick one that aligns with your learning goals.

---

## 12. Key Takeaways

- Signing workflows rely on deterministic hashes—understand what exactly you hash.
- When exposing previews, sanitize all content and keep it same-origin.
- Django’s `MEDIA_ROOT` + `static()` is enough for development but consider cloud storage in production.
- Python’s rich ecosystem (`cryptography`, `python-docx`) lets you build end-to-end document workflows without leaving the language.

Use this guide to walk classmates through the entire stack, from HTTP request to cryptographic signature and back to user experience. Happy building! 
