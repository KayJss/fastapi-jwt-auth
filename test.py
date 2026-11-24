import pytest # pyright: ignore[reportMissingImports]
from fastapi.testclient import TestClient # pyright: ignore[reportMissingImports]
import main as main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def gecici_veritabani(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test_users.db")
    main.tablo_olustur()

def test_register():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    assert response.status_code == 201

def test_register_wrongmail():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "testexample.com",
        "password": "Test123456"
    })
    assert response.status_code == 422
def test_register_shortpassword():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "T3456"
    })
    assert response.status_code == 400
def test_register_shortname():
    response = client.post("/register", json={
            "username": "TT",
            "email": "test@gmail.com",
            "password": "Test123456"
        })
    assert response.status_code == 400
def test_register_twice():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    assert response.status_code == 201
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    assert response.status_code == 409
def test_login_noexist():
        response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
        assert response.status_code == 401
def test_login_wrongpassword():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test1236"
    })
    assert response.status_code == 401
def test_login_nousername():
    response = client.post("/login", json={
        "username": "",
        "password": "Test1236"
    })
    assert response.status_code == 400
def test_login_80byte():
        response = client.post("/login", json={
        "username": "test123",
        "password": "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    })
        assert response.status_code == 400

def test_login_sucsess():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    assert main.verify_token(response.json()["access_token"])==1  

def test_sucsess_me():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    username = "TEST"
    email = "test@example.com"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    assert main.verify_token(response.json()["access_token"])==1
    token = response.json()["access_token"]
    response = client.get("/me", headers={
            "Authorization": "bearer" +" "+token ,
        })
    assert response.status_code == 200
    assert main.verify_token(token)==response.json()["id"]
    assert response.json()["username"]==username
    assert response.json()["email"]==email
def test_expired_token_me(monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_SECONDS","-1") 
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    username = "TEST"
    email = "test@example.com"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.get("/me", headers={
            "Authorization": "bearer" +" "+token ,
        })
    assert response.status_code ==401
def test_no_token_me():
    response = client.get("/me")
    assert response.status_code==401
def test_invalid_token_me():
    response = client.get("/me", headers={
            "Authorization": "bearer" +" "+"" ,
        })
    assert response.status_code==401





        



