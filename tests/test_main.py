import sys
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402


client = TestClient(main.app)


def signup_user(email: str = "Person@Example.com", password: str = "Password1") -> dict:
    response = client.post(
        "/auth/signup",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201
    return response.json()


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def reset_database(monkeypatch):
    test_db_dir = Path(__file__).resolve().parent / ".test_dbs"
    test_db_dir.mkdir(exist_ok=True)
    test_db_path = test_db_dir / f"{uuid.uuid4().hex}.db"
    monkeypatch.setattr(main, "DATABASE_PATH", test_db_path)
    main.LOGIN_ATTEMPTS.clear()
    main.init_db()
    yield
    for suffix in ("", "-wal", "-shm"):
        test_db_path.with_name(test_db_path.name + suffix).unlink(missing_ok=True)


def test_get_needs_returns_urgency_sorted_dummy_data():
    response = client.get("/needs")

    assert response.status_code == 200
    needs = response.json()
    urgencies = [need["urgency"] for need in needs]
    assert len(needs) == 5
    assert urgencies == sorted(urgencies, reverse=True)

    with main.get_db_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert journal_mode == "wal"


def test_create_need_validates_and_stores_trimmed_need():
    auth = signup_user()
    response = client.post(
        "/needs",
        headers=auth_headers(auth["access_token"]),
        json={
            "title": "  Water distribution  ",
            "location": "  Pune  ",
            "category": "Food",
            "urgency": 5,
            "description": "  Drinking water needed for residents  ",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == 6
    assert body["title"] == "Water distribution"
    assert body["location"] == "Pune"
    assert body["category"] == "food"
    assert body["urgency"] == 5
    assert len(client.get("/needs").json()) == 6

    with main.get_db_connection() as conn:
        created_at = conn.execute(
            "SELECT created_at FROM needs WHERE id = ?",
            (body["id"],),
        ).fetchone()[0]
    parsed = datetime.fromisoformat(created_at)
    assert parsed.tzinfo is not None
    assert created_at.endswith("+00:00")

    main.init_db()
    assert len(client.get("/needs").json()) == 6


@pytest.mark.parametrize(
    "payload",
    [
        {
            "title": "Invalid urgency",
            "location": "Delhi",
            "category": "food",
            "urgency": 6,
            "description": "Too urgent",
        },
        {
            "title": "Invalid category",
            "location": "Delhi",
            "category": "transport",
            "urgency": 3,
            "description": "Unsupported category",
        },
        {
            "title": "   ",
            "location": "Delhi",
            "category": "food",
            "urgency": 3,
            "description": "Blank title",
        },
    ],
)
def test_create_need_rejects_invalid_payloads(payload):
    auth = signup_user()
    response = client.post(
        "/needs",
        headers=auth_headers(auth["access_token"]),
        json=payload,
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "validation_error",
            "message": "Invalid request",
        }
    }


def test_match_requires_skills():
    response = client.get("/match")

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "missing_skills",
            "message": "Skills parameter required",
        }
    }
    assert client.get("/match", params={"skills": "   "}).status_code == 400


def test_match_returns_ranked_deterministic_reasons():
    response = client.get("/match", params={"skills": "food nurse"})

    assert response.status_code == 200
    matches = response.json()
    assert 0 < len(matches) <= 3
    assert matches[0]["category"] == "food"
    assert "Urgency 5/5" in matches[0]["reason"]
    assert "category match" in matches[0]["reason"]
    assert all(match["reason"] for match in matches)
    assert any(match["category"] == "medical" for match in matches)


def test_signup_normalizes_email_and_login_accepts_normalized_email():
    auth = signup_user(email="  PERSON@Example.COM  ", password="Password1")

    assert auth["token_type"] == "bearer"
    assert auth["user"]["email"] == "person@example.com"
    assert auth["user"]["role"] == "user"

    login_response = client.post(
        "/auth/login",
        json={"email": "person@example.com", "password": "Password1"},
    )

    assert login_response.status_code == 200
    assert login_response.json()["user"]["email"] == "person@example.com"


def test_jwt_payload_is_minimal():
    auth = signup_user()
    payload = json.loads(main._b64url_decode(auth["access_token"].split(".")[1]))

    assert set(payload) == {"sub", "role", "exp"}


@pytest.mark.parametrize("password", ["short1", "NoNumbersHere", "12345678"])
def test_signup_rejects_weak_passwords(password):
    response = client.post(
        "/auth/signup",
        json={"email": "person@example.com", "password": password},
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "validation_error",
            "message": "Invalid request",
        }
    }


def test_duplicate_signup_is_safe_error():
    signup_user(email="person@example.com", password="Password1")

    response = client.post(
        "/auth/signup",
        json={"email": "PERSON@example.com", "password": "Password1"},
    )

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "email_already_registered",
            "message": "Email already registered",
        }
    }


def test_login_rate_limit_after_repeated_failures():
    signup_user(email="person@example.com", password="Password1")

    for _ in range(main.LOGIN_ATTEMPT_LIMIT):
        response = client.post(
            "/auth/login",
            json={"email": "person@example.com", "password": "WrongPassword1"},
        )
        assert response.status_code == 401

    limited_response = client.post(
        "/auth/login",
        json={"email": "person@example.com", "password": "WrongPassword1"},
    )

    assert limited_response.status_code == 429
    assert limited_response.json() == {
        "error": {
            "code": "too_many_login_attempts",
            "message": "Too many login attempts. Please try again later.",
        }
    }


def test_create_need_requires_bearer_token():
    response = client.post(
        "/needs",
        json={
            "title": "Water distribution",
            "location": "Pune",
            "category": "food",
            "urgency": 5,
            "description": "Drinking water needed",
        },
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "auth_required",
            "message": "Authentication required",
        }
    }


@pytest.mark.parametrize(
    "authorization",
    ["Token abc", "Bearer", "Bearer one two"],
)
def test_authorization_header_format_is_strict(authorization):
    response = client.post(
        "/needs",
        headers={"Authorization": authorization},
        json={
            "title": "Water distribution",
            "location": "Pune",
            "category": "food",
            "urgency": 5,
            "description": "Drinking water needed",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_authorization_header"


def test_token_validation_errors_are_structured():
    auth = signup_user()
    token = auth["access_token"]
    bad_signature = f"{token[:-1]}x"
    expired_token = main.create_access_token(
        auth["user"]["id"],
        auth["user"]["role"],
        expires_in_seconds=-1,
    )

    malformed_response = client.post("/needs", headers=auth_headers("not-a-jwt"), json={})
    signature_response = client.post("/needs", headers=auth_headers(bad_signature), json={})
    expired_response = client.post("/needs", headers=auth_headers(expired_token), json={})

    assert malformed_response.status_code == 401
    assert malformed_response.json()["error"]["code"] == "malformed_token"
    assert signature_response.status_code == 401
    assert signature_response.json()["error"]["code"] == "invalid_token_signature"
    assert expired_response.status_code == 401
    assert expired_response.json()["error"]["code"] == "token_expired"


def test_token_is_revoked_after_password_change_timestamp():
    auth = signup_user()
    future_change = datetime.fromtimestamp(time.time() + 5, tz=timezone.utc)
    with main.get_db_connection() as conn:
        conn.execute(
            "UPDATE users SET last_password_change = ? WHERE id = ?",
            (future_change.isoformat(), auth["user"]["id"]),
        )
        conn.commit()

    response = client.post(
        "/needs",
        headers=auth_headers(auth["access_token"]),
        json={
            "title": "Water distribution",
            "location": "Pune",
            "category": "food",
            "urgency": 5,
            "description": "Drinking water needed",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "token_revoked"


def test_database_errors_are_sanitized(monkeypatch):
    monkeypatch.setattr(main, "DATABASE_PATH", Path(__file__).resolve().parent)

    response = client.get("/needs")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "database_error",
            "message": "Database operation failed",
        }
    }


def test_cors_allows_only_configured_origins():
    allowed_origin = main.ALLOWED_CORS_ORIGINS[0]
    allowed_response = client.options(
        "/needs",
        headers={
            "Origin": allowed_origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    blocked_response = client.options(
        "/needs",
        headers={
            "Origin": "https://example.invalid",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert allowed_response.headers["access-control-allow-origin"] == allowed_origin
    assert "access-control-allow-origin" not in blocked_response.headers


def test_cors_origins_reject_wildcard():
    with pytest.raises(ValueError):
        main._parse_cors_origins("http://localhost:3000,*")
