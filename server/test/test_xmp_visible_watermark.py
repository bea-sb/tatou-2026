import pytest

from src.xmp_visible_watermark import XMPVisibleWatermark
from src.watermarking_method import (
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
