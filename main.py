from fastapi import WebSocket, WebSocketDisconnect
from dotenv import load_dotenv
load_dotenv()

import os
print("SUPABASE_URL:", os.environ.get("SUPABASE_URL"))
print("SUPABASE_KEY exists:", bool(os.environ.get("SUPABASE_KEY")))
import json
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from supabase import create_client
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Dict, Optional

app = FastAPI()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

SECRET_KEY = os.environ.get("SECRET_KEY", "surworld_secret_key_very_long_string_123456789")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

ph = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# username -> WebSocket, активні підключення для realtime-мультиплеєру
active_connections: Dict[str, WebSocket] = {}


def get_user_from_ws_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

class RegisterRequest(BaseModel):
    username: str
    password: str

class SaveRequest(BaseModel):
    position_x: float
    position_y: float
    health: float
    hunger: float
    coins: int
    inventory: list
    customization: dict
    scene: str = "GameWorld"  # Додано поле scene

def create_token(username: str):
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register")
def register(data: RegisterRequest):
    existing = supabase.table("players").select("id").eq("username", data.username).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = ph.hash(data.password)
    supabase.table("players").insert({
        "username": data.username,
        "password_hash": hashed
    }).execute()
    return {"message": "Registered successfully"}

@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    result = supabase.table("players").select("*").eq("username", form.username).execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    player = result.data[0]
    try:
        ph.verify(player["password_hash"], form.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(form.username)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/player")
def get_player(username: str = Depends(get_current_user)):
    result = supabase.table("players").select("*").eq("username", username).execute()
    if not result.data:
        raise HTTPException(status_code=404, detail="Player not found")
    return result.data[0]

@app.post("/save")
def save_player(data: SaveRequest, username: str = Depends(get_current_user)):
    supabase.table("players").update({
        "position_x": data.position_x,
        "position_y": data.position_y,
        "health": data.health,
        "hunger": data.hunger,
        "coins": data.coins,
        "inventory": data.inventory,
        "customization": data.customization,
        "last_online": datetime.utcnow().isoformat()
    }).eq("username", username).execute()
    return {"message": "Saved"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    username = get_user_from_ws_token(token)
    if username is None:
        await websocket.close(code=1008)  # policy violation — невалідний токен
        return

    await websocket.accept()
    active_connections[username] = websocket

    # Повідомляємо всіх інших, що новий гравець зайшов
    await broadcast({"type": "player_joined", "username": username}, exclude=username)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except ValueError:
                continue

            data["username"] = username  # сервер сам підставляє, клієнту не довіряємо
            await broadcast(data, exclude=username)

    except WebSocketDisconnect:
        pass
    finally:
        active_connections.pop(username, None)
        await broadcast({"type": "player_left", "username": username}, exclude=username)


async def broadcast(message: dict, exclude: str = None):
    text = json.dumps(message)
    dead = []
    for uname, conn in active_connections.items():
        if uname == exclude:
            continue
        try:
            await conn.send_text(text)
        except Exception:
            dead.append(uname)

    # Прибираємо мертві з'єднання, якщо send провалився
    for uname in dead:
        active_connections.pop(uname, None)

@app.get("/")
def root():
    return {"status": "Surworld server running"}
