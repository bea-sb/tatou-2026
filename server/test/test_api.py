from server import app
from itsdangerous import URLSafeTimedSerializer
import server as server_module
import io
import datetime as dt
from types import SimpleNamespace

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

