from uuid import uuid4


def register_and_verify(client, email="new@example.com", full_name="New User"):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "StrongPassword123", "full_name": full_name},
    )
    assert response.status_code == 201
    code = response.json()["development_code"]
    response = client.post(
        "/api/v1/auth/verify-email",
        json={"email": email, "code": code},
    )
    assert response.status_code == 200
    return response.json()


def auth_header(auth):
    return {"Authorization": f"Bearer {auth['access_token']}"}


def test_email_auth_note_crud_profile_and_token_rotation(client):
    auth = register_and_verify(client)
    headers = auth_header(auth)

    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["email"] == "new@example.com"

    note_id = str(uuid4())
    created = client.post(
        "/api/v1/notes",
        headers=headers,
        json={"id": note_id, "title": "First", "details": "Body"},
    )
    assert created.status_code == 201
    assert created.json()["source"] == "neon"

    listed = client.get("/api/v1/notes", headers=headers)
    assert [item["id"] for item in listed.json()] == [note_id]

    updated = client.put(
        f"/api/v1/notes/{note_id}",
        headers=headers,
        json={"title": "Updated", "details": "Changed"},
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "Updated"

    profile = client.patch(
        "/api/v1/profile",
        headers=headers,
        data={"full_names": "Updated User"},
    )
    assert profile.status_code == 200
    assert profile.json()["full_name"] == "Updated User"

    refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": auth["refresh_token"]},
    )
    assert refresh.status_code == 200
    assert refresh.json()["refresh_token"] != auth["refresh_token"]
    replay = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": auth["refresh_token"]},
    )
    assert replay.status_code == 401

    deleted = client.delete(f"/api/v1/notes/{note_id}", headers=headers)
    assert deleted.status_code == 204
    assert client.get("/api/v1/notes", headers=headers).json() == []


def test_legacy_user_is_migrated_on_first_sign_in_and_rows_are_read_only(
    client, monkeypatch
):
    legacy_id = str(uuid4())
    old_note = {
        "id": str(uuid4()),
        "title": "Old note",
        "details": "Stored in Supabase",
        "created_at": "2023-01-01T00:00:00+00:00",
    }
    calls = []

    async def sign_in(email, password):
        calls.append(("auth", email, password))
        return {
            "user": {
                "id": legacy_id,
                "email": email,
                "email_confirmed_at": "2023-01-01T00:00:00Z",
                "user_metadata": {"full_name": "Legacy User"},
            }
        }

    async def get_user_data(user_id, table):
        calls.append((table, user_id))
        if table == "profiles":
            return [{"id": user_id, "full_names": "Legacy User", "picture": None}]
        if table == "notes":
            return [old_note]
        if table == "records":
            return []
        raise AssertionError(f"Unexpected legacy table: {table}")

    monkeypatch.setattr("app.main.legacy_supabase.sign_in", sign_in)
    monkeypatch.setattr("app.main.legacy_supabase.get_user_data", get_user_data)

    auth_response = client.post(
        "/api/v1/auth/login",
        json={"email": "old@example.com", "password": "OldPassword123"},
    )
    assert auth_response.status_code == 200
    auth = auth_response.json()
    headers = auth_header(auth)
    assert auth["user"]["id"] == legacy_id
    assert auth["user"]["full_name"] == "Legacy User"

    notes = client.get("/api/v1/notes", headers=headers).json()
    assert len(notes) == 1
    assert notes[0]["id"] == old_note["id"]
    assert notes[0]["source"] == "legacy"

    edited = client.put(
        f"/api/v1/notes/{old_note['id']}",
        headers=headers,
        json={"title": "Edited in Neon", "details": "Old source remains unchanged"},
    )
    assert edited.status_code == 200
    assert edited.json()["source"] == "legacy"
    assert old_note["title"] == "Old note"

    merged = client.get("/api/v1/notes", headers=headers).json()
    assert merged[0]["title"] == "Edited in Neon"
    assert calls.count(("auth", "old@example.com", "OldPassword123")) == 1

    subsequent_login = client.post(
        "/api/v1/auth/login",
        json={"email": "old@example.com", "password": "OldPassword123"},
    )
    assert subsequent_login.status_code == 200
    assert calls.count(("auth", "old@example.com", "OldPassword123")) == 1


def test_password_reset_revokes_existing_refresh_tokens(client):
    auth = register_and_verify(client, email="reset@example.com")
    request = client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "reset@example.com"},
    )
    assert request.status_code == 200
    code = request.json()["development_code"]
    reset = client.post(
        "/api/v1/auth/reset-password",
        json={
            "email": "reset@example.com",
            "code": code,
            "new_password": "NewStrongPassword456",
        },
    )
    assert reset.status_code == 200

    old_refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": auth["refresh_token"]},
    )
    assert old_refresh.status_code == 401

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "reset@example.com", "password": "NewStrongPassword456"},
    )
    assert login.status_code == 200
