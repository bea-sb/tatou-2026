import sys
from pathlib import Path

src_path = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(src_path))
#stand in tatou-2026/server when run :D

from server import app
from itsdangerous import URLSafeTimedSerializer
from types import SimpleNamespace
from werkzeug.security import generate_password_hash
import server as server_module
import io
import datetime as dt
from types import SimpleNamespace

slugify = app.config["SLUGIFY"] #get THE FUCNTION
sha256 = app.config["_SHA256_FILE"]
staticFiles = app.config["STATIC_FILES"]
getRmapDocId = app.config["GET_RMAP_DOC_ID"]
makeRmapWatrmrk = app.config["MAKE_RMAP_WATERMARK"]

class FakeUploadResult:
    def __init__(self, row=None, scalar_value=None):
        self.row = row
        self.scalar_value = scalar_value

    def scalar(self):
        return self.scalar_value

    def one(self):
        return self.row


class FakeUploadConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, statement, params=None):
        sql = str(statement)

        if "LAST_INSERT_ID()" in sql:
            return FakeUploadResult(scalar_value=1)

        if "SELECT id, name, creation" in sql:
            return FakeUploadResult(
                row=SimpleNamespace(
                    id=1,
                    name="test-document",
                    creation=dt.datetime(2026, 1, 1, 12, 0, 0),
                    sha256_hex="a" * 64,
                    size=13,
                )
            )

        return FakeUploadResult()


class FakeUploadEngine:
    def begin(self):
        return FakeUploadConnection()


class FakeRmapRes:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def first(self):
        return self.row

    def fetchall(self):
        return self.rows

class FakeRmapCon:
    def __init__(self, pdf_path):
        self.pdf_path = str(Path(pdf_path).resolve())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, statement, params=None):
        sql = str(statement)

        if "SELECT DATABASE(), @@hostname" in sql:
            return FakeRmapRes(
                row=("test_database", "test_host")
            )
        if "WHERE path = :path" in sql:
            if params["path"] == self.pdf_path:
                return FakeRmapRes(
                    row=SimpleNamespace(
                        id=1,
                        path=self.pdf_path,
                    )
                )
            return FakeRmapRes()
        if "FROM Documents" in sql:
            return FakeRmapRes(rows=[])
        return FakeRmapRes()

class FakeRMAPEngin:
        def __init__(self,pdf_path):
            self.pdf_path=pdf_path
        def connect(self):
            return FakeRmapCon(self.pdf_path)

class FakeWatrmrkCon:
    def __init__(self):
        self.inserted_params = None
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        return False
    def execute(self, statement, params=None):
        sql = str(statement)
        if "INSERT INTO Versions" in sql:
            self.inserted_params = params
        return FakeRmapRes()

class FakeWatermarkEngin:
    def __init__(self,pdf_path):
        self.pdf_path = str(Path(pdf_path).resolve())
        self.connection = FakeWatrmrkCon()
    def connect(self):
        return FakeRmapCon(self.pdf_path)
    def begin(self):
        return self.connection


def test_upload_document_returns_201(monkeypatch, tmp_path):
    client = authenticated_client(monkeypatch)

    # Use temporary storage and a fake database.
    monkeypatch.setitem(app.config, "STORAGE_DIR", tmp_path)
    monkeypatch.setitem(app.config, "_ENGINE", FakeUploadEngine())

    response = client.post(
        "/api/upload-document",
        data={
            "file": (io.BytesIO(b"Hello, Tatou!"), "test.txt"),
            "name": "test-document",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 201
    assert response.is_json

    data = response.get_json()
    assert data["id"] == 1
    assert data["name"] == "test-document"
    assert data["size"] == 13
    assert data["sha256"] == "a" * 64

    # Confirm the uploaded file was saved to temporary storage.
    user_dir = tmp_path / "files" / "test-user"
    assert user_dir.exists()
    assert len(list(user_dir.iterdir())) == 1

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

class FakeRowsResult:
    def __init__(self, rows=None):
        self.rows = rows or []

    def all(self):
        return self.rows

    def first(self):
        return self.rows[0] if self.rows else None


class FakeRowsConnection:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, *args, **kwargs):
        return FakeRowsResult(self.rows)


class FakeRowsEngine:
    def __init__(self, rows):
        self.rows = rows

    def connect(self):
        return FakeRowsConnection(self.rows)


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

'''''''''''''''
#Get-FileHash "C:\path\to\your-file.ext" -Algorithm SHA256
def test_sha256():
    path = Path("storage/Group_7.pdf")
    
    shaCon = sha256(path)

    group7pdf = "36BE4C21C916E75FE29B625C984ADBCEEF28E97B61A76A6C3AA777564FCD02E2"
    group7pdf=group7pdf.lower()

    assert group7pdf == shaCon
'''''''''

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

def test_rmapDocId(monkeypatch, tmp_path):
    #dont need authenticated user
    #is not auth

    #fakePDF instead
    pdf_path = tmp_path / "test-document.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\nTest PDF content\n%%EOF")

    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRMAPEngin(pdf_path)
    )

    #resp = client.get("/api/get-document/1")

    resp = getRmapDocId(pdf_path)
    assert resp == 1



#make_rmap_watermark

def test_makeRmapWatermark(monkeypatch, tmp_path):

    pdf_path = tmp_path / "orgi.pdf"
    pdf_path.write_bytes(
        b"%PDF-1.4\nOriginal PDF\n%%EOF"
    )

    fake_pdf_bytes = (
        b"%PDF-1.4\nFake watermarked PDF\n%%EOF"
    )

    fake_engine = FakeWatermarkEngin(pdf_path)

    monkeypatch.setitem(
        app.config, "_ENGINE", fake_engine
    )

    # Use the actual environment variable read by the function.
    monkeypatch.setenv("RMAP_KEY", "test-only-key")

    # Mock watermark processing so no real watermark is created.
    monkeypatch.setattr(
        server_module.WMUtils,
        "is_watermarking_applicable",
        lambda **kwargs: True,
    )

    monkeypatch.setattr(
        server_module.WMUtils,
        "apply_watermark",
        lambda **kwargs: fake_pdf_bytes,
    )

    # Point the function at our temporary original PDF.
    closure = dict(zip(
        makeRmapWatrmrk.__code__.co_freevars,
        makeRmapWatrmrk.__closure__ or (),
    ))

    if "RMAP_DOC" in closure:
        cell = closure["RMAP_DOC"]
        old_value = cell.cell_contents
        cell.cell_contents = str(pdf_path)

        try:
            resp = makeRmapWatrmrk(
                identity="testUsr",
                link="a" * 32,
            )
        finally:
            cell.cell_contents = old_value
    else:
        monkeypatch.setattr(
            server_module, "RMAP_DOC", str(pdf_path)
        )

        resp = makeRmapWatrmrk(
            identity="testUsr",
            link="a" * 32,
        )

    # Assert: file was created with the expected contents.
    assert resp.is_file()
    assert resp.name == f"orgi__{'a' * 32}.pdf"
    assert resp.read_bytes() == fake_pdf_bytes

    # Assert: database insertion happened.
    inserted = fake_engine.connection.inserted_params
    assert inserted is not None
    assert inserted["documentid"] == 1
    assert inserted["intended_for"] == "testUsr"
    assert inserted["link"] == "a" * 32
    assert inserted["method"] == "xmp-visible"
    assert inserted["path"] == str(resp)






def test_create_user_requires_fields():
    client = app.test_client()

    resp = client.post("/api/create-user", json={})

    assert resp.status_code == 400
    assert "required" in resp.get_json()["error"]


def test_login_requires_credentials():
    client = app.test_client()

    resp = client.post("/api/login", json={})

    assert resp.status_code == 400
    assert resp.get_json()["error"] == "email and password are required"


def test_list_documents_requires_authentication():
    client = app.test_client()

    resp = client.get("/api/list-documents")

    assert resp.status_code in (401, 403)


def test_list_versions_requires_authentication():
    client = app.test_client()

    resp = client.get("/api/list-versions/11")

    assert resp.status_code in (401, 403)

def test_get_watermarking_methods_returns_json():
    client = app.test_client()

    resp = client.get("/api/get-watermarking-methods")

    assert resp.status_code == 200
    assert resp.is_json

    data = resp.get_json()
    assert "methods" in data
    assert "count" in data
    assert data["count"] == len(data["methods"])


def get_route_closure_vars(route_name):
    view = app.view_functions[route_name]
    return dict(zip(
        view.__code__.co_freevars,
        (cell.cell_contents for cell in view.__closure__ or ()),
    ))


def get_rmap_server():
    return get_route_closure_vars("rmap_getlink_msg2")["server"]


def test_rmap_getlink_msg2_returns_200(monkeypatch):
    client = app.test_client()
    view = app.view_functions["rmap_getlink_msg2"]

    closure_vars = get_route_closure_vars("rmap_getlink_msg2")
    rmap_server = closure_vars["server"]

    # Mock the handshake so it doesn't perform real RMAP processing.
    monkeypatch.setattr(
        rmap_server,
        "receiveMsg2",
        lambda info: (
            "test-identity",
            "b" * 32,
            {"status": "ok"},
        ),
    )

    # Find the closure cell containing the local watermark function.
    freevars = view.__code__.co_freevars
    closure_cells = dict(zip(freevars, view.__closure__ or ()))

    assert "make_rmap_watermark" in closure_cells, (
        f"Available closure variables: {list(closure_cells)}"
    )

    watermark_cell = closure_cells["make_rmap_watermark"]
    original_watermark_function = watermark_cell.cell_contents

    # Replace it temporarily to prevent real database/file operations.
    watermark_cell.cell_contents = lambda **kwargs: None

    try:
        resp = client.post(
            "/api/rmap-get-link",
            json={"msg2": "test-message"},
        )
    finally:
        # Restore the original closure function.
        watermark_cell.cell_contents = original_watermark_function

    assert resp.status_code == 200, (
        f"Response status: {resp.status_code}; "
        f"response body: {resp.get_json()}"
    )
    assert resp.get_json() == {"status": "ok"}

def test_list_documents_returns_200(monkeypatch):
    client = authenticated_client(monkeypatch)

    fake_document = SimpleNamespace(
        id=1,
        name="test-document.pdf",
        creation=dt.datetime(2026, 1, 1, 12, 0, 0),
        sha256_hex="a" * 64,
        size=1024,
    )

    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRowsEngine([fake_document]),
    )

    resp = client.get("/api/list-documents")

    assert resp.status_code == 200
    assert resp.is_json

    data = resp.get_json()
    assert "documents" in data
    assert len(data["documents"]) == 1

    document = data["documents"][0]
    assert document["id"] == 1
    assert document["name"] == "test-document.pdf"
    assert document["creation"] == "2026-01-01T12:00:00"
    assert document["sha256"] == "a" * 64
    assert document["size"] == 1024


def test_list_versions_returns_200(monkeypatch):
    client = authenticated_client(monkeypatch)

    fake_version = SimpleNamespace(
        id=7,
        documentid=1,
        link="a" * 32,
        intended_for="test-user",
        secret="test-secret",
        method="xmp-visible",
    )

    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRowsEngine([fake_version]),
    )

    resp = client.get("/api/list-versions/1")

    assert resp.status_code == 200
    assert resp.is_json

    data = resp.get_json()
    assert "versions" in data
    assert len(data["versions"]) == 1

    version = data["versions"][0]
    assert version["id"] == 7
    assert version["documentid"] == 1
    assert version["link"] == "a" * 32
    assert version["method"] == "xmp-visible"
    assert version["intended_for"] == "test-user"

def test_list_all_versions_returns_200(monkeypatch):
    client = authenticated_client(monkeypatch)

    fake_version = SimpleNamespace(
        id=7,
        documentid=1,
        link="b" * 32,
        intended_for="test-user",
        method="xmp-visible",
    )

    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRowsEngine([fake_version]),
    )

    resp = client.get("/api/list-all-versions")

    assert resp.status_code == 200
    assert resp.is_json

    data = resp.get_json()
    assert "versions" in data
    assert len(data["versions"]) == 1

    version = data["versions"][0]
    assert version["id"] == 7
    assert version["documentid"] == 1
    assert version["link"] == "b" * 32
    assert version["intended_for"] == "test-user"
    assert version["method"] == "xmp-visible"


def test_get_document_returns_200(monkeypatch, tmp_path):
    client = authenticated_client(monkeypatch)

    # Create a temporary file inside the configured storage directory.
    monkeypatch.setitem(app.config, "STORAGE_DIR", tmp_path)
    pdf_path = tmp_path / "test-document.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\nTest PDF content\n%%EOF")

    fake_document = SimpleNamespace(
        id=1,
        name="test-document.pdf",
        path=str(pdf_path),
        sha256_hex="a" * 64,
        size=31,
    )

    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRowsEngine([fake_document]),
    )

    resp = client.get("/api/get-document/1")

    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data == b"%PDF-1.4\nTest PDF content\n%%EOF"
    assert resp.headers["Cache-Control"] == (
        "private, max-age=0, must-revalidate"
    )
    assert resp.headers["ETag"] == f'"{"a" * 64}"'
    assert "inline" in resp.headers.get("Content-Disposition", "").lower()



def test_get_doc_returns_200(monkeypatch, tmp_path):
    client = app.test_client()

    # Create the temporary watermarks directory
    watermarks_dir = tmp_path / "watermarks"
    watermarks_dir.mkdir()

    # Create a fake watermarked PDF
    pdf_path = watermarks_dir / "test-watermarked.pdf"
    pdf_content = b"%PDF-1.4\nTest RMAP watermarked PDF\n%%EOF"
    pdf_path.write_bytes(pdf_content)

    # Valid 32-character hexadecimal token
    token = "a" * 32

    # Mock the database row
    fake_version = SimpleNamespace(
        link=token,
        intended_for="test-user",
        path=str(pdf_path),
    )

    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRowsEngine([fake_version]),
    )

    # Patch the closure cell captured by the get_doc route.
    view = app.view_functions["get_doc"]
    freevars = view.__code__.co_freevars
    closure_cells = dict(zip(freevars, view.__closure__ or ()))

    assert "RMAP_DOC" in closure_cells

    rmap_doc_cell = closure_cells["RMAP_DOC"]
    original_rmap_doc = rmap_doc_cell.cell_contents

    rmap_doc_cell.cell_contents = str(tmp_path / "rmap-document.pdf")

    try:
        resp = client.get(f"/get-doc/{token}")
    finally:
        # Restore the original value after the request
        rmap_doc_cell.cell_contents = original_rmap_doc

    # Verify the PDF response
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data == pdf_content
    assert "inline" in resp.headers.get(
        "Content-Disposition", ""
    ).lower()


def test_get_version_returns_200(monkeypatch, tmp_path):
    client = app.test_client()

    # Use a temporary storage directory and create a fake PDF
    monkeypatch.setitem(app.config, "STORAGE_DIR", tmp_path)
    pdf_path = tmp_path / "test-version.pdf"
    pdf_content = b"%PDF-1.4\nTest watermarked PDF content\n%%EOF"
    pdf_path.write_bytes(pdf_content)

    # Mock the database row returned by the Versions query
    fake_version = SimpleNamespace(
        link="test-version",
        path=str(pdf_path),
    )
    monkeypatch.setitem(
        app.config,
        "_ENGINE",
        FakeRowsEngine([fake_version]),
    )

    resp = client.get("/api/get-version/test-version")

    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert resp.data == pdf_content
    assert resp.headers["Cache-Control"] == "private, max-age=0"
    assert "inline" in resp.headers.get("Content-Disposition", "").lower()