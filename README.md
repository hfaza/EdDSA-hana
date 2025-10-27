# EdDSA-hana

Local Django application for exploring Ed25519 (EdDSA) signing and verification of Microsoft Word documents. The original Google Colab notebook has been reworked into a reusable web UI that stores all inputs and outputs on the local filesystem.

## Prerequisites

- Python 3.11 or newer
- Recommended: virtual environment (`python3 -m venv venv && source venv/bin/activate`)

## Installation

```bash
pip install -r requirements.txt
python manage.py migrate
```

The project does not require a database, but running `migrate` initializes Django internals.

## Run the App

```bash
python manage.py runserver
```

Then open http://127.0.0.1:8000/ to access the web UI.
With the server running in DEBUG mode, template and static changes trigger automatic browser refresh via `django-browser-reload`.

## Signing Workflow

1. Pick a `.docx` file on the **Sign Document** card.
2. Submit the form to generate:
   - Ed25519 signature (`*.sig`)
   - Public key in PEM format (`*_public.pem`)
   - Document digest (EdDSA) (`*_digest.txt`)
   - A copy of the original document
3. Outputs are written to `media/sessions/<session-id>/` for local storage and are downloadable from the success message.

## Verification Workflow

1. Provide the document, signature, and public key generated earlier in the **Verify Signature** card.
2. The app recomputes the SHA-256 digest from `word/document.xml` and validates the signature locally.
3. A success or failure banner explains whether the inputs match.

## Project Structure

- `signer/utils.py` packages the EdDSA hashing, signing, and verification helpers.
- `signer/views.py` orchestrates file handling without database storage.
- `signer/templates/signer/` contains the minimal frontend wired to Django forms.
- `media/` is automatically created to keep session artifacts out of source control (add to `.gitignore` if committing).

Extend the app by surfacing additional metadata, enforcing stronger file validation, or integrating tests with `pytest`.
