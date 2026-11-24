import pytest # pyright: ignore[reportMissingImports]
from starlette.testclient import TestClient as TestClient # pyright: ignore[reportMissingImports]
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
    assert response.status_code == 401 or response.status_code == 403
def test_invalid_token_me():
    response = client.get("/me", headers={
            "Authorization": "bearer" +" "+"ffff" ,
        })
    assert response.status_code == 401 or response.status_code == 403


def test_sucsess_changepassword():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+token ,
        },json={
             "old_password":password,
             "new_password":"Test1234567"
        })
    assert response.status_code == 200

def test_notoken_changepassword():
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
    response = client.put("/password",json={
             "old_password":"Test1234567",
             "new_password":"Test1234567"
        })
    assert response.status_code == 401 or response.status_code == 403


def test_expired_changepassword(monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_SECONDS","-1") 
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+token ,
        },json={
             "old_password":password,
             "new_password":"Test1234567"
        })
    assert response.status_code == 401 or response.status_code == 403
def test_wrongtoken_changepassword():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+"test" ,
        },json={
             "old_password":password,
             "new_password":"Test1234567"
        })
    assert response.status_code == 401 or response.status_code == 403

def test_sucsess_changepassword_and_login():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+token ,
        },json={
             "old_password":password,
             "new_password":"Test1234567"
        })
    assert response.status_code == 200
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test1234567"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
def test_sucsess_changepassword_oldpass():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+token ,
        },json={
             "old_password":password,
             "new_password":"Test1234567"
        })
    assert response.status_code == 200
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 401

def test_short_changepassword():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+token ,
        },json={
             "old_password":password,
             "new_password":"T"
        })
    assert response.status_code == 400


def test_wrongpass_changepassword():
    response = client.post("/register", json={
        "username": "TEST",
        "email": "test@example.com",
        "password": "Test123456"
    })
    password = "Test123456"
    assert response.status_code == 201
    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    response = client.put("/password", headers={
            "Authorization": "bearer" +" "+token ,
        },json={
             "old_password":"Test1234567",
             "new_password":"Test1234567"
        })
    assert response.status_code == 401
@pytest.fixture
def account_token():
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
    return response.json()["access_token"]


def test_delete_success(account_token):
    response = client.request(
        "DELETE", "/delete",
        headers={"Authorization": f"Bearer {account_token}"},
        json={"password": "Test123456"}
    )
    assert response.status_code == 200


def test_delete_wrong_password(account_token):
    response = client.request(
        "DELETE", "/delete",
        headers={"Authorization": f"Bearer {account_token}"},
        json={"password": "WrongPassword"}
    )
    assert response.status_code == 401


def test_delete_invalid_token():
    response = client.request(
        "DELETE", "/delete",
        headers={"Authorization": "Bearer invalidtoken"},
        json={"password": "Test123456"}
    )
    assert response.status_code == 401


def test_delete_no_token():
    response = client.request(
        "DELETE", "/delete",
        json={"password": "Test123456"}
    )
    assert response.status_code in (401, 403)


def test_login_deleted_account(account_token):
    response = client.request(
        "DELETE", "/delete",
        headers={"Authorization": f"Bearer {account_token}"},
        json={"password": "Test123456"}
    )
    assert response.status_code == 200

    response = client.post("/login", json={
        "username": "TEST",
        "password": "Test123456"
    })
    assert response.status_code == 401


def test_deleted_account_token(account_token):
    response = client.request(
        "DELETE", "/delete",
        headers={"Authorization": f"Bearer {account_token}"},
        json={"password": "Test123456"}
    )
    assert response.status_code == 200

    response = client.get("/me", headers={
        "Authorization": f"Bearer {account_token}"
    })
    assert response.status_code == 404


def test_deleted_id_not_reused(account_token):
    old_id = main.verify_token(account_token)
    assert old_id is not None

    response = client.request(
        "DELETE", "/delete",
        headers={"Authorization": f"Bearer {account_token}"},
        json={"password": "Test123456"}
    )
    assert response.status_code == 200

    response = client.post("/register", json={
        "username": "NEWUSER",
        "email": "new@example.com",
        "password": "Test123456"
    })
    assert response.status_code == 201

    response = client.post("/login", json={
        "username": "NEWUSER",
        "password": "Test123456"
    })
    assert response.status_code == 200

    new_id = main.verify_token(response.json()["access_token"])

    assert new_id is not None
    assert new_id > old_id

    response = client.get("/me", headers={
        "Authorization": f"Bearer {account_token}"
    })
    assert response.status_code == 404