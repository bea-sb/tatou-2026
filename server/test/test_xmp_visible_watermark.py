import pytest

from xmp_visible_watermark import XMPVisibleWatermark
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
)


def make_pdf() -> bytes:
    import fitz

    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text(
        (72, 72),
        "Tatou test document",
    )

    data = doc.tobytes()
    doc.close()

    return data


def test_add_and_read_secret():
    method = XMPVisibleWatermark()

    pdf = make_pdf()

    position = (
        '{"position":"bottom-right",'
        '"intended_for":"Alice"}'
    )

    watermarked = method.add_watermark(
        pdf=pdf,
        secret="my secret",
        key="my key",
        position=position,
    )

    assert watermarked.startswith(b"%PDF-")

    recovered = method.read_secret(
        pdf=watermarked,
        key="my key",
    )

    assert recovered == "my secret"


def test_wrong_key():
    method = XMPVisibleWatermark()

    watermarked = method.add_watermark(
        pdf=make_pdf(),
        secret="my secret",
        key="correct key",
    )

    with pytest.raises(InvalidKeyError):
        method.read_secret(
            pdf=watermarked,
            key="wrong key",
        )


def test_missing_watermark():
    method = XMPVisibleWatermark()

    with pytest.raises(SecretNotFoundError):
        method.read_secret(
            pdf=make_pdf(),
            key="my key",
        )


def test_empty_intended_for():
    method = XMPVisibleWatermark()

    watermarked = method.add_watermark(
        pdf=make_pdf(),
        secret="my secret",
        key="my key",
        position='{"position":"bottom-right","intended_for":""}',
    )

    assert method.read_secret(
        pdf=watermarked,
        key="my key",
    ) == "my secret"

def test_xmp_contains_encrypted_secret():
    import fitz

    method = XMPVisibleWatermark()

    watermarked = method.add_watermark(
        pdf=make_pdf(),
        secret="my secret",
        key="my key",
    )

    doc = fitz.open(
        stream=watermarked,
        filetype="pdf",
    )

    try:
        xmp = doc.get_xml_metadata()
    finally:
        doc.close()

    assert xmp
    assert XMPVisibleWatermark.XMP_NAMESPACE in xmp
    assert XMPVisibleWatermark.XMP_PROPERTY in xmp

def test_secret_is_not_stored_as_plaintext():
    method = XMPVisibleWatermark()

    secret = "this is my very secret watermark"

    watermarked = method.add_watermark(
        pdf=make_pdf(),
        secret=secret,
        key="my key",
    )

    assert secret.encode("utf-8") not in watermarked

def test_xmp_encrypted_value_round_trip():
    import base64
    import fitz
    import xml.etree.ElementTree as ET

    method = XMPVisibleWatermark()

    secret = "my secret"
    key = "my key"

    watermarked = method.add_watermark(
        pdf=make_pdf(),
        secret=secret,
        key=key,
    )

    doc = fitz.open(
        stream=watermarked,
        filetype="pdf",
    )

    try:
        xmp = doc.get_xml_metadata()
    finally:
        doc.close()

    root = ET.fromstring(xmp)

    property_tag = (
        f"{{{method.XMP_NAMESPACE}}}"
        f"{method.XMP_PROPERTY}"
    )

    element = root.find(
        f".//{property_tag}"
    )

    assert element is not None
    assert element.text

    encrypted = base64.b64decode(
        element.text,
        validate=True,
    )

    assert encrypted != secret.encode("utf-8")

    decrypted = method._decrypt_secret(
        encrypted,
        key,
    )

    assert decrypted == secret

