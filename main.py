from pathlib import Path
import sqlite3
import bcrypt # pyright: ignore[reportMissingImports]
from fastapi import FastAPI, HTTPException # type: ignore
from pydantic import BaseModel,EmailStr # type: ignore # pyright: ignore[reportUndefinedVariable]
from datetime import date, datetime, time, timedelta,UTC
import jwt # pyright: ignore[reportMissingImports]


app = FastAPI()
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password:str
class LoginRequest(BaseModel):
    username: str
    password:str

def get_token(self, expires=600):
    payload = {
        'user_id': self.id,
        'exp': datetime.now(UTC) + timedelta(seconds=expires),
        'used': False

    }
    return jwt.encode(payload, "SECRET-KEY", algorithm="HS256")

@staticmethod
def verify_token(token):
    try:
        payload = jwt.decode(token, "SECRET-KEY", algorithms=['HS256'])
        if datetime.now(UTC) <= datetime.fromtimestamp(payload['exp'], UTC) and not payload['used']:
            user_id = payload['user_id']
            payload['used'] = True
            return user_id
        else:
            return None

    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def hashlama(sifre:str):
    try:
     if(not sifre.strip()):
         raise HTTPException(status_code=400, detail="Şifre Boşluk olamaz")
     elif(len(sifre)<8):
         raise HTTPException(status_code=400, detail="Şifre 8 Karakterden küçük olamaz")
     elif len(sifre.encode("utf-8")) > 72:
         raise HTTPException(status_code=400, detail="Şifre 72 Byte'dan Büyük olamaz")

     else:
        sifrebytes = sifre.encode('utf-8')
        salt = bcrypt.gensalt()
        hash2 = bcrypt.hashpw(sifrebytes, salt)
        return hash2.decode("utf-8")
    except ValueError:
        raise HTTPException(status_code=400, detail="Geçersiz bir veri girdiniz")

    

DB_PATH = Path(__file__).with_name("users.db")

def baglan():
    return sqlite3.connect(DB_PATH)
def tablo_olustur():
    baglanti = baglan()
    try:
        cursor = baglanti.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        baglanti.commit()
    finally:
        baglanti.close()


tablo_olustur()

@app.post("/register",status_code=201) # pyright: ignore[reportUndefinedVariable]
def register(user:RegisterRequest):
    baglanti = baglan()
    try:
        cursor = baglanti.cursor()
        if(not user.username.strip()):
            raise HTTPException(status_code=400, detail="Kullanıcı adı boş olamaz")
        elif(len(user.username) < 3 or len(user.username)>32):
            raise HTTPException(status_code=400, detail="Kullanıcı 3 haneden küçük yada 32 haneden büyük olamaz")
        elif(" " in user.username):
             raise HTTPException(status_code=400, detail="Kullanıcı adı boşluk olamaz")
        else:
            cursor.execute(
            """INSERT INTO users (username, email, password_hash)
                           VALUES (?, ?, ?)""",
                        (user.username,user.email, hashlama(user.password),
                    ))
            baglanti.commit()
            return {"Mesaj": "Kullanıcı Başarıyla Oluşturuldu"}

    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Kullanıcı adı yada email Sistemde kayıtlı!")
    finally:
        baglanti.close()
@app.post("/login",status_code=200) # pyright: ignore[reportUndefinedVariable]
def login(user:LoginRequest):
    baglanti = baglan()
    try:
        cursor = baglanti.cursor()
        cursor.execute("SELECT username,password_hash FROM users WHERE username = ?",(user.username,))
        sonuc = cursor.fetchone()
        if(not user.username.strip()):
            raise HTTPException(status_code=400, detail="Kullanıcı adı boş olamaz")
        elif len(user.password.encode("utf-8")) > 72:
            raise HTTPException(status_code=400, detail="Şifre 72 Byte'dan Büyük olamaz")
        elif(sonuc is None):
            raise HTTPException(status_code=401, detail="Şifre yada Kullanıcı Adı Yanlış!")
        elif not bcrypt.checkpw(user.password.encode("utf-8"), sonuc[1].encode("utf-8")):
            raise HTTPException(status_code=401, detail="Şifre yada Kullanıcı Adı Yanlış!")
        else:
            return {"Mesaj": "Başarıyla Giriş Yapıldı"}
        
        

        

        
    finally:
        baglanti.close()
    