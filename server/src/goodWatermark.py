from __future__ import annotations
from io import BytesIO
import json
import base64
import hashlib
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from reportlab.lib.utils import ImageReader
from PyPDF2 import PdfReader, PdfWriter
from typing import Final




from watermarking_method import (
    PdfSource,
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

class GoodWatermarker(WatermarkingMethod):
    #give name reg can find
    name: Final[str] = "Good-Watermarker-Generator"


    @staticmethod
    def get_usage() -> str:
        return "Does not change Position my good sir, blah blah blah.. Should add watermark to every page if need be"

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        #add things here
        #secret=group identity :P could be

        intended_for = ""
        if position:
            try:
                config = json.loads(position)
                if isinstance(config,dict):
                    intended_for = config.get("intended_for", "")
            except (json.JSONDecodeError,TypeError):
                intended_for = ""

        #make string
        if not isinstance(intended_for,str):
            intended_for = str(intended_for)
        intended_for=intended_for.strip()
        #have backup
        if not intended_for:
            intended_for="recipent not stated :P"


        if not secret:
            raise ValueError("watermark secret is empty, fill it please *hands you a shovel*")

        IMAGE_PATH1 = (Path(__file__).resolve().parent / "stamp" /"Bee.png")
        if not IMAGE_PATH1.is_file():
            raise FileNotFoundError(f"Waterstamp image not found: {IMAGE_PATH1}")
        
        IMAGE_PATH2 = (Path(__file__).resolve().parent / "stamp" /"superman-kills-zod1.jpg")
        if not IMAGE_PATH2.is_file():
            raise FileNotFoundError(f"Waterstamp image not found: {IMAGE_PATH2}")

        image1 = ImageReader(str(IMAGE_PATH1))
        image2 = ImageReader(str(IMAGE_PATH2))

        org_bytes = load_pdf_bytes(pdf)

        input_file = BytesIO(org_bytes)
        input_pdf = PdfReader(input_file)
        if len(input_pdf.pages) == 0:
            raise ValueError("pdf has no pages")

        firstPage= input_pdf.pages[0]
        width=float(firstPage.mediabox.width)
        height=float(firstPage.mediabox.height)

        watermark_buffer=BytesIO()
        watermarkPDF = canvas.Canvas(watermark_buffer, pagesize=(width,height))
        watermarkPDF.setFillColor(colors.grey)
        watermarkPDF.setFont("Helvetica", 10)
        watermarkPDF.drawCentredString(300,50, intended_for) #X, Y

        watermarkPDF.drawImage(image1, 450, 25, width=100, height= 50, mask="auto")
        watermarkPDF.drawImage(image2, 100, 650, width=100, height= 50, mask="auto")

        crypt=self._encrypt_sec(secret,key)
        hidden=base64.b64encode(crypt).decode("ascii")
        watermarkPDF.setFont("Helvetica",1)
        watermarkPDF._code.append("3 Tr")
        watermarkPDF.drawString(1,1,f"BeansInSoock{hidden}")
        watermarkPDF._code.append("0 Tr")

        watermarkPDF.save()
        watermark_buffer.seek(0)

        watermarkPDF = PdfReader(watermark_buffer)

        watermarkPage = watermarkPDF.pages[0]
        output = PdfWriter()

        for i in range(len(input_pdf.pages)):
            page = input_pdf.pages[i]
            page.merge_page(watermarkPage)
            output.add_page(page)

        output_buff = BytesIO()
        output.write(output_buff)

        return output_buff.getvalue()

    AAD: Final[bytes] = b"tatou/good-watermarker/v1"

    def is_watermark_applicable(
        self,
        pdf: PdfSource, #pathtofile,
        position: str | None = None,
    ) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            reader = BytesIO(data)
            reader = PdfReader(reader)
            return len(reader.pages) > 0
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str)->str:
        #dot hings here
        data = load_pdf_bytes(pdf)
        marker="BeansInSoock"
        try:
            reader = BytesIO(data)
            reader = PdfReader(reader)
            for page in reader.pages:
                text=page.extract_text() or ""
                if marker in text:
                    hidden = text.split(marker,1)[1]
                    hidden = hidden.split()[0].strip()

                    try:
                        encrypted=base64.b64decode(hidden, validate=True)
                    except Exception as e:
                        raise WatermarkingError("invalid encoding") from e
                    return self._decrypt(encrypted,key)
            raise SecretNotFoundError("no good secret")
        except (SecretNotFoundError, InvalidKeyError):
            raise 
        except Exception as e:
            raise WatermarkingError(f"fail to read watermark: {e}") from e


    @staticmethod
    def _key(key: str) -> bytes:
        if not isinstance(key, str)or not key:
            raise InvalidKeyError("Key must be filled")
        return hashlib.sha512(key.encode("utf-8")).digest()
    @classmethod
    def _encrypt_sec(cls, secret: str, key:str) -> bytes:
        billCipher=AESSIV(cls._key(key))
        return billCipher.encrypt(secret.encode("utf-8"),[cls.AAD])
    @classmethod
    def _decrypt(cls, encrypted: bytes, key:str) -> str:
        billCipher= AESSIV(cls._key(key))
        try:
            text=billCipher.decrypt(encrypted,[cls.AAD])
        except Exception as e:
            raise InvalidKeyError("key is wrong or watermark corrupt") from e
        return text.decode("utf-8")

__all__ = ["GoodWatermarker"]