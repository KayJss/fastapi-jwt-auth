import pytest # pyright: ignore[reportMissingImports]
from fastapi.testclient import TestClient # pyright: ignore[reportMissingImports]
import main as main3

client = TestClient(main3.app)


@pytest.fixture(autouse=True)
def gecici_veritabani(tmp_path, monkeypatch):
    monkeypatch.setattr(main3, "DB_PATH", tmp_path / "test_users.db")
    main3.tablo_olustur()

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
