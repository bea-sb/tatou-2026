import sys
from pathlib import Path

src_path = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(src_path))
#stand in tatou-2026/server when run :D

from server import app
from itsdangerous import URLSafeTimedSerializer
from types import SimpleNamespace
from werkzeug.security import generate_password_hash

slugify = app.config["SLUGIFY"] #get THE FUCNTION
sha256 = app.config["_SHA256_FILE"]
staticFiles = app.config["STATIC_FILES"]


class FakeResult:
    def first(self):
        return None


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, *args, **kwargs):
        return FakeResult()


class FakeEngine:
    def connect(self):
        return FakeConnection()


class FakeResult2:
    def __init__(self, row=None):
        self.row = row
    def first(self):
        return self.row

class FakeConnection2:
    def __init__(self, row=None):
        self.row = row
    def __enter__(self):
        return self
    def __exit__(self, exc_type,exc_value, traceback):
        return False
    def execute(self, *args, **kwargs):
        return FakeResult2(self.row)

class FakeEngine2:
    def __init__(self, row=None):
        self.row = row
    def connect(self):
        return FakeConnection2(self.row)


def authenticated_client(monkeypatch):
    # Replace the database engine with a fake that finds no owned document.
    monkeypatch.setitem(app.config, "_ENGINE", FakeEngine())

    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="tatou-auth",
    )
    token = serializer.dumps({
        "uid": 1,
        "login": "test-user",
        "email": None,
    })

    client = app.test_client()
    client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    
def test_read_watermark_requires_authentication():
    client = app.test_client()
    resp = client.post("/api/read-watermark")

    assert resp.status_code in (401, 403)


def test_delete_document_requires_authentication():
    client = app.test_client()
    resp = client.delete("/api/delete-document/9")

    assert resp.status_code in (401, 403)


def test_rmap_initiate_rejects_missing_json():
    client = app.test_client()
    resp = client.post(
        "/api/rmap-initiate",
        content_type="application/json",
    )

    assert resp.status_code >= 400

def test_read_watermark_denies_document_not_owned(monkeypatch):
    client = authenticated_client(monkeypatch)

    resp = client.post(
        "/api/read-watermark/9",
        json={"method": "test", "key": "test-key"},
    )

    assert resp.status_code == 404
    assert resp.get_json()["error"] == "document not found"


def test_delete_document_denies_document_not_owned(monkeypatch):
    client = authenticated_client(monkeypatch)

    resp = client.delete("/api/delete-document/9")

    assert resp.status_code == 404
    assert resp.get_json()["error"] == "document not found"




def test_slugify(): #checks that work as intended
    assert slugify("I absolutely lobe bananas") == "i-absolutely-lobe-bananas"
    assert slugify("   ") == "individual-copy"
    assert slugify("- --") == "individual-copy"
    assert slugify(" ") == "individual-copy"
    assert slugify("!!") == "individual-copy"
    assert slugify("   My Tummy!! hurts") == "my-tummy-hurts"

def test_home():
    client = app.test_client()
    resp = client.get("/") #call the route
    
    assert resp.status_code == 200 #check page success
    assert resp.mimetype == "text/html" #response be html
    assert b"<html lang=" in resp.data.lower()
    assert b"Upload PDFs, create watermarked versions, and share secure public links." in resp.data

#Get-FileHash "C:\path\to\your-file.ext" -Algorithm SHA256
def test_sha256():
    path = Path("storage/Group_7.pdf")
    
    shaCon = sha256(path)

    group7pdf = "36BE4C21C916E75FE29B625C984ADBCEEF28E97B61A76A6C3AA777564FCD02E2"
    group7pdf=group7pdf.lower()

    assert group7pdf == shaCon

def test_staticFiles():
    #resp = staticFiles("/index.html")
    #assert resp.status_code == 200
    
    client = app.test_client()
    resp = client.get("/index.html")
    assert resp.status_code == 200
    

def test_login_succ(monkeypatch): #200
    fake_user = SimpleNamespace(id =420, email= "test@test.yes", login= "testerUser", hpassword= generate_password_hash("test"))
    
    monkeypatch.setitem(app.config, "_ENGINE", FakeEngine2(fake_user))
    client = app.test_client()
    resp = client.post("/api/login", json={"email": "test@test.yes", "password": "test"})
    assert resp.status_code == 200

#get_rmap_doc_id

def test_rmapDocId():
    ""

    resp = ""
    assert resp.status_code == 200

#make_rmap_watermark

def test_makeRmapWatermark():
    ""

    resp = ""
    assert resp.status_code == 200