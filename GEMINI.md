# GEMINI.md

## Project Overview

This project is a Django web application that allows users to digitally sign and verify Microsoft Word (`.docx`) documents using the Ed25519 (EdDSA) signature algorithm. It provides a simple web interface for signing documents and verifying their authenticity.

The core technologies used are:

*   **Backend:** Django
*   **Cryptography:** `cryptography` library for EdDSA signing and verification.
*   **File Handling:** `python-docx` for parsing `.docx` files.

The application is structured as a single Django app called `signer`. The main logic for signing and verification is encapsulated in `signer/utils.py`, while `signer/views.py` handles the web requests and responses. The frontend is a simple HTML template located in `signer/templates/signer/home.html`.

## Building and Running

### Prerequisites

*   Python 3.11 or newer
*   A virtual environment is recommended.

### Installation

1.  Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```
3.  Initialize the database:
    ```bash
    python manage.py migrate
    ```

### Running the Application

1.  Start the Django development server:
    ```bash
    python manage.py runserver
    ```
2.  Open your web browser and navigate to `http://127.0.0.1:8000/`.

## Development Conventions

*   The core cryptographic logic is separated into `signer/utils.py`.
*   The application uses Django forms for handling user input and file uploads.
*   File artifacts from the signing process are stored in the `media/sessions/` directory. Each session has a unique ID.
*   The application generates an HTML preview of the uploaded `.docx` file for user convenience.
*   The `django-browser-reload` library is used for automatic browser refresh during development.
