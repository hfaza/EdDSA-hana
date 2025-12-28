from django import forms


class DocumentSignForm(forms.Form):
    document = forms.FileField(
        label="Select DOCX to sign",
        help_text="Upload a .docx file to generate a signature and public key.",
    )


class DocumentVerifyForm(forms.Form):
    document = forms.FileField(
        label="Document to verify",
        help_text="Upload the .docx file that should match the signature.",
    )
    signature = forms.FileField(
        label="Signature file",
        help_text="Provide the .png QR code signature file.",
    )
    public_key = forms.FileField(
        label="Public key",
        help_text="Provide the .pem public key paired with the signature.",
    )
