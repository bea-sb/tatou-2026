from __future__ import annotations

import base64
import hashlib
import json
from typing import Final
import xml.etree.ElementTree as ET

import fitz
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class XMPVisibleWatermark(WatermarkingMethod):
    """
    Visible watermark + encrypted secret stored in XMP metadata.

    The visible watermark is placed on every page.

    `position` can be either a simple position:

        "bottom-right"

    or a JSON configuration:

        {
            "position": "bottom-right",
            "intended_for": "Alice"
        }

    The secret is never stored as plaintext in the PDF. It is encrypted
    with AES-SIV using a deterministic key derived from the supplied key.
    """

    name: Final[str] = "xmp-visible"

    DEFAULT_VISIBLE_TEXT: Final[str] = (
        "your individual copy, do not share"
    )

    DEFAULT_POSITION: Final[str] = "bottom-right"

    VALID_POSITIONS: Final[frozenset[str]] = frozenset(
        {
            "bottom-right",
            "bottom-left",
            "top-right",
            "top-left",
            "center",
        }
    )

    # Stable namespace identifying Tatou's watermark metadata.
    XMP_NAMESPACE: Final[str] = (
        "https://tatou.local/ns/watermark/1.0/"
    )

    XMP_PREFIX: Final[str] = "tatou"

    XMP_PROPERTY: Final[str] = "EncryptedSecret"

    # AES-SIV is deterministic and authenticated.
    AAD: Final[bytes] = b"tatou/xmp-visible/v1"

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    @staticmethod
    def get_usage() -> str:
        return (
            "Visible watermark with encrypted XMP metadata. "
            "Supported positions: bottom-right, bottom-left, "
            "top-right, top-left, center. "
            "For intended_for which is the visible watermark, position may be a JSON object such as "
            '{"position":"bottom-right","intended_for":"Alice"}. '
            "If intended_for is empty, the visible watermark is "
            '"your individual copy, do not share".'
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)

        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")

        actual_position, intended_for = self._parse_position(position)

        if actual_position not in self.VALID_POSITIONS:
            raise ValueError(
                f"Unknown watermark position: {actual_position!r}. "
                f"Expected one of: {sorted(self.VALID_POSITIONS)}"
            )

        visible_text = self._visible_text(intended_for)

        # Validate the key before modifying the PDF.
        encrypted_secret = self._encrypt_secret(secret, key)

        doc: fitz.Document | None = None

        try:
            doc = fitz.open(stream=data, filetype="pdf")

            if doc.page_count == 0:
                raise WatermarkingError(
                    "Cannot watermark a PDF with no pages"
                )

            self._add_visible_watermark(
                doc,
                visible_text,
                actual_position,
            )

            self._set_encrypted_secret(
                doc,
                encrypted_secret,
            )

            return doc.tobytes()

        except WatermarkingError:
            raise
        except Exception as exc:
            raise WatermarkingError(
                f"Failed to add watermark: {exc}"
            ) from exc
        finally:
            if doc is not None:
                doc.close()

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        data = load_pdf_bytes(pdf)

        actual_position, _ = self._parse_position(position)

        if actual_position not in self.VALID_POSITIONS:
            return False

        doc: fitz.Document | None = None

        try:
            doc = fitz.open(stream=data, filetype="pdf")

            if doc.page_count == 0:
                return False

            for page in doc:
                self._watermark_rect(
                    page.rect,
                    actual_position,
                )

            return True

        except Exception:
            return False
        finally:
            if doc is not None:
                doc.close()

    def read_secret(
        self,
        pdf: PdfSource,
        key: str,
    ) -> str:
        data = load_pdf_bytes(pdf)

        doc: fitz.Document | None = None

        try:
            doc = fitz.open(stream=data, filetype="pdf")

            encrypted_secret = self._get_encrypted_secret(doc)

            return self._decrypt_secret(
                encrypted_secret,
                key,
            )

        finally:
            if doc is not None:
                doc.close()

    # ---------------------------------------------------------
    # Position / visible text
    # ---------------------------------------------------------

    @classmethod
    def _parse_position(
        cls,
        position: str | None,
    ) -> tuple[str, str]:
        """
        Parse the method-specific position configuration.

        Returns:
            (actual_position, intended_for)
        """

        if not position:
            return cls.DEFAULT_POSITION, ""

        # New format:
        #
        # {
        #     "position": "bottom-right",
        #     "intended_for": "Alice"
        # }
        try:
            config = json.loads(position)
        except json.JSONDecodeError:
            config = None

        if isinstance(config, dict):
            actual_position = config.get(
                "position",
                cls.DEFAULT_POSITION,
            )

            intended_for = config.get(
                "intended_for",
                "",
            )

            if not isinstance(actual_position, str):
                raise ValueError(
                    "position must be a string"
                )

            if not isinstance(intended_for, str):
                raise ValueError(
                    "intended_for must be a string"
                )

            return actual_position, intended_for

        # Backwards-compatible simple position:
        return position, ""

    @classmethod
    def _visible_text(cls, intended_for: str) -> str:
        intended_for = intended_for.strip()

        if not intended_for:
            return cls.DEFAULT_VISIBLE_TEXT

        return intended_for

    # ---------------------------------------------------------
    # Encryption
    # ---------------------------------------------------------

    @staticmethod
    def _derive_key(key: str) -> bytes:
        if not isinstance(key, str) or not key:
            raise InvalidKeyError(
                "Key must be a non-empty string"
            )

        # AESSIV accepts a 64-byte key.
        return hashlib.sha512(
            key.encode("utf-8")
        ).digest()

    @classmethod
    def _encrypt_secret(
        cls,
        secret: str,
        key: str,
    ) -> bytes:
        cipher = AESSIV(
            cls._derive_key(key)
        )

        return cipher.encrypt(
            secret.encode("utf-8"),
            [cls.AAD],
        )

    @classmethod
    def _decrypt_secret(
        cls,
        encrypted: bytes,
        key: str,
    ) -> str:
        cipher = AESSIV(
            cls._derive_key(key)
        )

        try:
            plaintext = cipher.decrypt(
                encrypted,
                [cls.AAD],
            )
        except Exception as exc:
            raise InvalidKeyError(
                "The supplied key is incorrect or "
                "the watermark has been corrupted"
            ) from exc

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WatermarkingError(
                "The decrypted secret is not valid UTF-8"
            ) from exc

    # ---------------------------------------------------------
    # Visible watermark
    # ---------------------------------------------------------

    @classmethod
    def _watermark_rect(
        cls,
        page_rect: fitz.Rect,
        position: str,
    ) -> fitz.Rect:
        margin = 24
        width = min(
            300,
            page_rect.width - 2 * margin,
        )
        height = 32

        if width <= 0 or page_rect.height <= height + 2 * margin:
            raise WatermarkingError(
                "PDF page is too small for the visible watermark"
            )

        if position == "bottom-right":
            return fitz.Rect(
                page_rect.x1 - margin - width,
                page_rect.y1 - margin - height,
                page_rect.x1 - margin,
                page_rect.y1 - margin,
            )

        if position == "bottom-left":
            return fitz.Rect(
                page_rect.x0 + margin,
                page_rect.y1 - margin - height,
                page_rect.x0 + margin + width,
                page_rect.y1 - margin,
            )

        if position == "top-right":
            return fitz.Rect(
                page_rect.x1 - margin - width,
                page_rect.y0 + margin,
                page_rect.x1 - margin,
                page_rect.y0 + margin + height,
            )

        if position == "top-left":
            return fitz.Rect(
                page_rect.x0 + margin,
                page_rect.y0 + margin,
                page_rect.x0 + margin + width,
                page_rect.y0 + margin + height,
            )

        if position == "center":
            return fitz.Rect(
                page_rect.x0 + (page_rect.width - width) / 2,
                page_rect.y0 + (page_rect.height - height) / 2,
                page_rect.x0 + (page_rect.width + width) / 2,
                page_rect.y0 + (page_rect.height + height) / 2,
            )

        raise ValueError(
            f"Unknown watermark position: {position!r}"
        )

    @classmethod
    def _add_visible_watermark(
        cls,
        doc: fitz.Document,
        text: str,
        position: str,
    ) -> None:
        for page in doc:
            rect = cls._watermark_rect(
                page.rect,
                position,
            )

            page.insert_textbox(
                rect,
                text,
                fontsize=10,
                fontname="helv",
                align=fitz.TEXT_ALIGN_CENTER,
                overlay=True,
            )

    # ---------------------------------------------------------
    # XMP handling
    # ---------------------------------------------------------

    @classmethod
    def _set_encrypted_secret(
        cls,
        doc: fitz.Document,
        encrypted_secret: bytes,
    ) -> None:
        """
        Add/update Tatou's encrypted secret while preserving
        existing XMP metadata where possible.
        """

        encoded = base64.b64encode(
            encrypted_secret
        ).decode("ascii")

        existing_xmp = doc.get_xml_metadata()

        if not existing_xmp:
            root = cls._new_xmp_root()
        else:
            try:
                root = ET.fromstring(existing_xmp)
            except ET.ParseError:
                # Existing XMP is malformed. We don't want malformed
                # metadata to prevent watermarking the PDF.
                root = cls._new_xmp_root()

        rdf = cls._find_or_create_rdf(root)
        description = cls._find_or_create_description(rdf)

        property_tag = (
            f"{{{cls.XMP_NAMESPACE}}}"
            f"{cls.XMP_PROPERTY}"
        )

        # Remove an old Tatou secret if one exists.
        for child in list(description):
            if child.tag == property_tag:
                description.remove(child)

        ET.SubElement(
            description,
            property_tag,
        ).text = encoded

        ET.register_namespace(
            "rdf",
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        )
        ET.register_namespace(
            "x",
            "adobe:ns:meta/",
        )
        ET.register_namespace(
            cls.XMP_PREFIX,
            cls.XMP_NAMESPACE,
        )

        xml_bytes = ET.tostring(
            root,
            encoding="utf-8",
            xml_declaration=False,
        )

        doc.set_xml_metadata(
            xml_bytes.decode("utf-8")
        )

    @classmethod
    def _new_xmp_root(cls) -> ET.Element:
        xmpmeta = ET.Element(
            "{adobe:ns:meta/}xmpmeta"
        )

        ET.SubElement(
            xmpmeta,
            "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF",
        )

        return xmpmeta

    @classmethod
    def _find_or_create_rdf(
        cls,
        root: ET.Element,
    ) -> ET.Element:
        rdf_namespace = (
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        )

        rdf = root.find(
            f"{{{rdf_namespace}}}RDF"
        )

        if rdf is None:
            rdf = ET.SubElement(
                root,
                f"{{{rdf_namespace}}}RDF",
            )

        return rdf

    @classmethod
    def _find_or_create_description(
        cls,
        rdf: ET.Element,
    ) -> ET.Element:
        rdf_namespace = (
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        )

        description = rdf.find(
            f"{{{rdf_namespace}}}Description"
        )

        if description is None:
            description = ET.SubElement(
                rdf,
                f"{{{rdf_namespace}}}Description",
            )

        return description

    @classmethod
    def _get_encrypted_secret(
        cls,
        doc: fitz.Document,
    ) -> bytes:
        xmp = doc.get_xml_metadata()

        if not xmp:
            raise SecretNotFoundError(
                "No XMP metadata found"
            )

        try:
            root = ET.fromstring(xmp)
        except ET.ParseError as exc:
            raise SecretNotFoundError(
                "The PDF contains invalid XMP metadata"
            ) from exc

        property_tag = (
            f"{{{cls.XMP_NAMESPACE}}}"
            f"{cls.XMP_PROPERTY}"
        )

        element = root.find(
            f".//{property_tag}"
        )

        if element is None or not element.text:
            raise SecretNotFoundError(
                "No Tatou encrypted secret found "
                "in the PDF XMP metadata"
            )

        try:
            return base64.b64decode(
                element.text,
                validate=True,
            )
        except Exception as exc:
            raise WatermarkingError(
                "The encrypted secret in XMP metadata "
                "is not valid Base64"
            ) from exc


__all__ = [
    "XMPVisibleWatermark",
]
