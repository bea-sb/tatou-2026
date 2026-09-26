import os
import io
import hashlib
import datetime as dt
import secrets
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from rmap import ( #=we want those seperate error messages thingies if need be
    RMAPServer,
    RMAPError,
    MalformedMessageException,
    UnknownIdentityException,
    DecryptionException,
    UnsupportedKeyException,
    PassphraseRequiredException,
    ProtocolStateException,
)


import pickle as _std_pickle
try:
    import dill as _pickle  # allows loading classes not importable by module path
except Exception:  # dill is optional
    _pickle = _std_pickle


import watermarking_utils as WMUtils
from watermarking_method import WatermarkingMethod
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- RMAP ---
    #probably but that in database instead of i flask annars kommer de sluta fungera senare
    #if flask restart all links lost
    #sessions = {}
    #= RMAP path
    RMAP_DOC=os.environ.get("RMAP_DOC")

    server = RMAPServer(
        server_public_key_path="keys/server_pub.asc",
        server_private_key_path="keys/server_priv.asc",
        passphrase= os.environ.get("PASSPHRASE"),      # or None if the key isn't protected
        linkPrefix="http://localhost:5000/get-doc/",
        verbose=True,
    )
    print("RMAP LINK PREFIX:", server.linkPrefix)
    server.loadIdentities("keys/clients/")

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---
    
    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")
    
    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            return jsonify({"error": "invalid credentials"}), 401

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        fname = file.filename

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200



    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    
    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200


    ##-- RMAPstuff --##
    #=get rmap doc 
    def get_rmap_doc_id(pdf_file):

        pdf_path = str(Path(pdf_file).resolve())

        with get_engine().connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT id, path
                    FROM Documents
                    WHERE path = :path
                    LIMIT 1
                    """
                    ),
                {"path" : pdf_path},
            ).first()

        if not row:
            raise ValueError(f"RMAP source doc not registeres: {pdf_path}")
        return row.id
        
    #= make sure watermodel is chanegs
    #cant habe jsonify if iys not a @app thingy needs to make into exceptions
    #@app.post("/make-rmap-watermark/<identity:link>") #maybe not have flask endpoint just server
    def make_rmap_watermark(identity, link, position=None):
        
        #check that path thingy works
        if not RMAP_DOC:
            return RuntimeError({"error" : "rmap is not configures yet"})

        pdf_file= Path(RMAP_DOC).resolve() #pathtofile resolve just in case for consistensy *nerd emoji*

        if not pdf_file.is_file(): #if it aint a file
            raise FileNotFoundError("the original file is missing")

        # CHECK LINK IMMEDITAELTY
        if len(link) != 32:
            raise ValueError("invalid RMAP linky")
        try:
            int(link, 16)
        except ValueError:
            raise ValueError("invalid RMAP linku")

        document_id = get_rmap_doc_id(pdf_file)

        #select watermark method or our method
        waterMethod= "Good Watermarker Generator"
        #generate secret/key
        secret=identity
        key="rmap" #unused rn by watermethod

        position=position or None
    
        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=waterMethod,
                pdf=str(pdf_file),
                #secret=secret,
                #key=key,
                position=position
            )
        except Exception as e:
            raise RuntimeError(f"watermark applic check fail: {e}") from e
            
        if applicable is False:
            raise ValueError("watermark meth not applicaböle")

        #save pdf and apply
        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(pdf_file),
                secret=secret,
                key=key,
                method=waterMethod,
                position=position
            )

        except Exception as e:
            raise RuntimeError(f"watermark fail: {e}") from e

        if not isinstance(wm_bytes, (bytes, bytearray)) or not wm_bytes:
            raise RuntimeError("watermark no output")

        #fix destination
        # build destination file name: "<original_name>__<intended_to>.pdf"
        watermark_dir = pdf_file.parent / "watermarks"
        watermark_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{pdf_file.stem}__{link}.pdf"
        dest_path = watermark_dir / filename

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            raise RuntimeError(f"failed to write watermark file: {e}") from e
        
        
        if not dest_path.is_file() or dest_path.stat().st_size == 0:
            raise IOError(f"Watermarked PDF was not created: {dest_path}")

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions 
                        (documentid, link, intended_for, secret, method, position, path)
                        
                        VALUES 
                        (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": document_id,
                        "link": link,
                        "intended_for": identity,
                        "secret": secret,
                        "method": waterMethod,
                        "position": position or "",
                        "path": str(dest_path), #do string just to be safe
                    },
                )
        except Exception:
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise
            #we should check that the rmap watermarked version is actually in there

        return dest_path


    #=msg1
    @app.post("/rmap-initiate-msg1")
    def rmap_initiate_msg1():

        info = request.get_json(silent=True) #silent true to stop badrequest before own errors

        if not info:
            return jsonify({"error" : "missing json bod"}), 400 #Bad Reques
        try:
            identity, resp1 = server.receiveMsg1(info)

            return jsonify(resp1), 200
        
        #add some rmaperrors
        except UnknownIdentityException as e: #put more specific error/exception first
                    return jsonify({"error": "Unknown Identity"}), 401
        except RMAPError as e:
            return jsonify({"error": f"RMAP failed: {e}"}), 400
        #EXCEPTION specifyprevents false silent failures
        except Exception as e:
            return jsonify({"error" : "rmap msg1 initate failed"}), 400#Bad Requesserver cannot process request

    #=msg2
    @app.post("/rmap-getlink-msg2")
    def rmap_getlink_msg2():

        info = request.get_json(silent=True)#should we add silent=true here?

        #we should add some error messages or
        #pick up if its empty null etc
        if not info:
            return jsonify({"error" : "missing json bod, something is missing"}), 400
        try:
            # expectedLink is always just the bare 32-hex-char link, even
            # though the value inside resp2 itself is prefixed with
            # linkPrefix - use expectedLink as your internal session key,
            # e.g. to remember which identity completed which handshake.

            identity, expectedLink, resp2 = server.receiveMsg2(info)

            make_rmap_watermark(
                identity=identity,
                link= expectedLink
            )
            return jsonify(resp2), 200
        #add some rmaperrors
        #put specific ones first otherwise they wont be catched and understood
        except UnknownIdentityException as e:
            return jsonify({"error": "Unknown Identity"}), 401
        except RMAPError:
            return jsonify({"Error": "rmap fail"}), 400
        except FileNotFoundError as e:
            return jsonify({"error" : str(e)}), 500
        except Exception as e:
            return jsonify({
                "error": f"rmap watermark creation failed: {e}"
            }), 500
    

    #=cant have document twice as get-document already taken
    #and maybe we need one for the rmap
    @app.get("/get-doc/<token>") #token instead of ID
    def get_doc(token):

        #maybe check that the token actually is 32 hexadecimal char like
        #it should be as per instructionsss
        if len(token) != 32:
            return jsonify({"error": "not 32, invalid rmap link"}), 400

        try:
            int(token,16)
        except ValueError:
            return jsonify({"error": "not 32 invalid rmap linky"}), 400

        #we put in db instead of dict
        #follow what get_document and Create_watermark does lookuo datadabse
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT link, intended_for, path
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                        """
                    ),
                    {"link": token},
                ).first()
        except Exception as e:
            app.logger.exception("DATABASE ERROR") #show in docker logs -f tatou-
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
                return jsonify({"error": "document not found"}), 404
        
        file_path = Path(row.path).resolve()#resolve just in case

        storage_dir = Path(app.config["STORAGE_DIR"]).resolve()
        rmap_watermark_dir = (Path(RMAP_DOC).resolve().parent / "watermarks").resolve()

        try:
            file_path.relative_to(rmap_watermark_dir)
        except ValueError:
            return jsonify({"error": "doc path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "fille missing on le disk"}), 410

        send=send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=file_path.name, #we dont have row
            conditional=True,
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        # :P
        return send


    
        

    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
    
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400
        
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    #@require_auth #=dshould we add??? NO it crashes our systesm,, probabli intentional no auth
    def get_version(link: str):
        
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth #=NEED AUTH otherwise someone should be able to delete documensts #=AUTGH ADDED
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        # Fetch the document (enforce ownership)
        try:
            with get_engine().connect() as conn:
                query = "SELECT * FROM Documents WHERE id = " + doc_id
                row = conn.execute(text(query)).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning("Failed to delete file %s for doc id=%s: %s", fp, row.id, e)
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on Version.documentid,
                # uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"), {"id": doc_id})
                conn.execute(text("DELETE FROM Documents WHERE id = :id"), {"id": doc_id})
        except Exception as e:
            return jsonify({"error": f"database error during delete: {str(e)}"}), 503

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_error,   # null/omitted if everything was fine
        }), 200
        
        
    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on GET
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)
        #=change to hash 256 make a unique parameter hash to not make doubles with same name and stuff
        unique=hashlib.sha256(f"{doc_id}:{intended_for}:{secret}:{dt.datetime.now(dt.UTC).isoformat()}".encode()).hexdigest()[:32]


        #candidate = f"{base_name}__{intended_slug}.pdf" #= can probably create same thing twoce lets add unique to make sure it doesnt make doubles
        candidate = f"{base_name}__{intended_slug}__{unique}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token = sha1(watermarked_file_name)
        #link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
        link_token = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:32]  #= change from sha1 generally unsafer to sha256 considered better and :32 its supposd to be 32

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201


    #### THIS ONE VERY SCARYand not required in specifications file and 
    # we are scared of pickles  
    #=F PICLES REMOVED
    
    
    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
            
        return jsonify({"methods": methods, "count": len(methods)}), 200
        
    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400
            
        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document; FIXME enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": doc_id},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410
        
        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201


    """
    Server-side implementation of the RMAP protocol.

    IMPORTANT: RMAP itself does not implement, require, or assume any HTTP
    route for retrieving whatever the link ultimately unlocks, nor any
    particular route names for the handshake endpoints themselves. This
    library only handles the 4-message PGP handshake (msg1/resp1/msg2/resp2)
    and computing the resulting `expectedLink` string. Your endpoint names
    (e.g. "/msg1" vs "/api/rmap-initiate") and what the link value even
    represents (a document ID, a session token, part of a URL, or nothing
    URL-related at all) are entirely up to your Flask app. `expectedLink`
    itself is just an opaque string you can use as a session/lookup key
    however your project needs.

    The decrypted resp2 payload is `{"result": "<link>"}` (matching this
    course's API spec).

    Typical usage inside a Flask app (the route names and linkPrefix below
    are just one example of how a project *might* choose to expose things):

    """





    return app
    

# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

