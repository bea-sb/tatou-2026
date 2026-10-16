from server import app
from itsdangerous import URLSafeTimedSerializer

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