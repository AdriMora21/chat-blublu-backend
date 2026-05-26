from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException, Depends, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import random
import string
import hashlib
import uuid
import bcrypt
import jwt
from pathlib import Path
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

MONGO_URL = os.environ['MONGO_URL']
DB_NAME = os.environ['DB_NAME']
JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret-change-me')
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRES_DAYS = int(os.environ.get('JWT_EXPIRES_DAYS', '30'))

mongo_client = AsyncIOMotorClient(MONGO_URL)
db = mongo_client[DB_NAME]

users_col = db.cb_users
rooms_col = db.cb_rooms
messages_col = db.cb_messages

MESSAGE_TTL_SECONDS = 48 * 60 * 60
ROOM_CODE_LENGTH = 6
ROOM_ALPHABET = string.ascii_uppercase + string.digits

app = FastAPI(title="Chat Blublu API")
api_router = APIRouter(prefix="/api")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ===== Helpers =====
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_jwt(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "iat": utc_now(),
        "exp": utc_now() + timedelta(days=JWT_EXPIRES_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None


def anon_nickname_for(user_id: str, room_code: str) -> str:
    h = hashlib.sha256(f"{user_id}:{room_code}".encode()).hexdigest()
    return f"Anon{int(h[:6], 16) % 10000:04d}"


async def generate_room_code() -> str:
    while True:
        code = "".join(random.choice(ROOM_ALPHABET) for _ in range(ROOM_CODE_LENGTH))
        if not await rooms_col.find_one({"code": code}, {"_id": 0, "code": 1}):
            return code


# ===== Pydantic Models =====
class RegisterIn(BaseModel):
    username: str
    password: str


class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: str
    username: str
    role: str


class AuthResponse(BaseModel):
    token: str
    user: UserOut


class RoomCreateResponse(BaseModel):
    code: str


class RoomExistsResponse(BaseModel):
    exists: bool
    participants: int = 0


class MessageOut(BaseModel):
    username: str
    body: str
    timestamp: str


class HistoryResponse(BaseModel):
    messages: List[MessageOut]


class AdminUserOut(BaseModel):
    id: str
    username: str
    role: str
    created_at: str


# ===== Auth Dependencies =====
async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sessão inválida ou expirada",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exc
    payload = decode_jwt(token)
    if not payload or "sub" not in payload:
        raise credentials_exc
    user = await users_col.find_one({"id": payload["sub"]}, {"_id": 0, "hashed_password": 0})
    if not user:
        raise credentials_exc
    return user


async def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    return current_user


# ===== WebSocket Connection Manager =====
class RoomConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.user_info: Dict[WebSocket, dict] = {}

    async def connect(self, websocket: WebSocket, room_code: str, anon: str, user_id: str) -> None:
        await websocket.accept()
        self.active_connections.setdefault(room_code, []).append(websocket)
        self.user_info[websocket] = {"room_code": room_code, "anon": anon, "user_id": user_id}

    def disconnect(self, websocket: WebSocket) -> Optional[dict]:
        info = self.user_info.pop(websocket, None)
        if not info:
            return None
        room_code = info["room_code"]
        if room_code in self.active_connections:
            try:
                self.active_connections[room_code].remove(websocket)
            except ValueError:
                pass
            if not self.active_connections[room_code]:
                del self.active_connections[room_code]
        return info

    def participants(self, room_code: str) -> List[str]:
        conns = self.active_connections.get(room_code, [])
        return [self.user_info[c]["anon"] for c in conns if c in self.user_info]

    def participant_count(self, room_code: str) -> int:
        return len(self.active_connections.get(room_code, []))

    async def broadcast(self, room_code: str, message: dict) -> None:
        if room_code not in self.active_connections:
            return
        dead = []
        for conn in list(self.active_connections[room_code]):
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for d in dead:
            self.disconnect(d)


room_manager = RoomConnectionManager()


# ===== Startup =====
@app.on_event("startup")
async def init_indexes():
    await messages_col.create_index(
        "created_at", expireAfterSeconds=MESSAGE_TTL_SECONDS, name="ttl_created_at"
    )
    await messages_col.create_index([("room_code", 1), ("created_at", 1)])
    await rooms_col.create_index("code", unique=True)
    await users_col.create_index("username", unique=True)
    await users_col.create_index("id", unique=True)


@app.on_event("shutdown")
async def shutdown_db_client():
    mongo_client.close()


# ===== HTTP Routes — Public =====
@api_router.get("/")
async def root():
    return {"message": "Chat Blublu API", "status": "ok"}


@api_router.get("/download/chat-blublu.zip")
async def download_source_zip():
    zip_path = "/app/chat-blublu.zip"
    if not os.path.exists(zip_path):
        raise HTTPException(status_code=404, detail="ZIP not found")
    return FileResponse(zip_path, media_type="application/zip", filename="chat-blublu.zip")


# ===== Auth Routes =====
@api_router.post("/auth/register", response_model=AuthResponse)
async def register(body: RegisterIn):
    username = body.username.strip()
    password = body.password
    if len(username) < 2 or len(username) > 32:
        raise HTTPException(status_code=400, detail="Nome deve ter 2 a 32 caracteres")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Palavra-passe deve ter pelo menos 4 caracteres")

    existing = await users_col.find_one({"username": username}, {"_id": 0, "id": 1})
    if existing:
        raise HTTPException(status_code=409, detail="Nome já existe")

    total_users = await users_col.count_documents({})
    role = "admin" if total_users == 0 else "user"

    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "username": username,
        "hashed_password": hash_password(password),
        "role": role,
        "created_at": utc_now(),
    }
    await users_col.insert_one(doc)
    logger.info(f"User registered: {username} (role={role})")

    token = create_jwt(user_id, role)
    return AuthResponse(
        token=token,
        user=UserOut(id=user_id, username=username, role=role),
    )


@api_router.post("/auth/login", response_model=AuthResponse)
async def login(body: LoginIn):
    username = body.username.strip()
    user = await users_col.find_one({"username": username})
    if not user or not verify_password(body.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=401, detail="Nome ou palavra-passe incorreta")
    token = create_jwt(user["id"], user["role"])
    return AuthResponse(
        token=token,
        user=UserOut(id=user["id"], username=user["username"], role=user["role"]),
    )


@api_router.get("/auth/me", response_model=UserOut)
async def me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return UserOut(id=current_user["id"], username=current_user["username"], role=current_user["role"])


# ===== Room Routes (protected) =====
@api_router.post("/rooms", response_model=RoomCreateResponse)
async def create_room(current_user: Dict[str, Any] = Depends(get_current_user)):
    code = await generate_room_code()
    await rooms_col.insert_one({
        "code": code,
        "owner_id": current_user["id"],
        "created_at": utc_now(),
    })
    logger.info(f"Room {code} created by {current_user['username']}")
    return RoomCreateResponse(code=code)


@api_router.get("/rooms/{code}", response_model=RoomExistsResponse)
async def check_room(code: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    code = code.upper().strip()
    found = await rooms_col.find_one({"code": code}, {"_id": 0, "code": 1})
    if found:
        return RoomExistsResponse(exists=True, participants=room_manager.participant_count(code))
    return RoomExistsResponse(exists=False, participants=0)


@api_router.get("/rooms/{code}/messages", response_model=HistoryResponse)
async def get_room_history(
    code: str,
    limit: int = 200,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    code = code.upper().strip()
    cutoff = utc_now() - timedelta(seconds=MESSAGE_TTL_SECONDS)
    cursor = messages_col.find(
        {"room_code": code, "created_at": {"$gte": cutoff}},
        {"_id": 0, "anon": 1, "body": 1, "created_at": 1},
    ).sort("created_at", 1).limit(max(1, min(limit, 500)))
    docs = await cursor.to_list(length=500)
    msgs = [
        MessageOut(
            username=d.get("anon", "Anon"),
            body=d["body"],
            timestamp=d["created_at"].isoformat() if isinstance(d["created_at"], datetime) else str(d["created_at"]),
        )
        for d in docs
    ]
    return HistoryResponse(messages=msgs)


@api_router.delete("/rooms/{code}")
async def delete_room(code: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    code = code.upper().strip()
    room = await rooms_col.find_one({"code": code}, {"_id": 0})
    if not room:
        raise HTTPException(status_code=404, detail="Sala não encontrada")
    if current_user["role"] != "admin" and room.get("owner_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Sem permissão para apagar esta sala")
    await rooms_col.delete_one({"code": code})
    await messages_col.delete_many({"room_code": code})
    return {"deleted": True, "code": code}


# ===== Admin Routes =====
@api_router.get("/admin/users", response_model=List[AdminUserOut])
async def admin_list_users(current_user: Dict[str, Any] = Depends(require_admin)):
    cursor = users_col.find({}, {"_id": 0, "id": 1, "username": 1, "role": 1, "created_at": 1}).sort("created_at", -1)
    docs = await cursor.to_list(length=1000)
    return [
        AdminUserOut(
            id=d["id"],
            username=d["username"],
            role=d["role"],
            created_at=d["created_at"].isoformat() if isinstance(d.get("created_at"), datetime) else str(d.get("created_at", "")),
        )
        for d in docs
    ]


@api_router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, current_user: Dict[str, Any] = Depends(require_admin)):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Não podes apagar a tua própria conta")
    target = await users_col.find_one({"id": user_id}, {"_id": 0, "id": 1, "username": 1})
    if not target:
        raise HTTPException(status_code=404, detail="Utilizador não encontrado")
    await users_col.delete_one({"id": user_id})
    rooms = await rooms_col.find({"owner_id": user_id}, {"_id": 0, "code": 1}).to_list(length=10000)
    codes = [r["code"] for r in rooms]
    if codes:
        await messages_col.delete_many({"room_code": {"$in": codes}})
        await rooms_col.delete_many({"owner_id": user_id})
    logger.info(f"Admin {current_user['username']} deleted user {target['username']}")
    return {"deleted": True, "username": target["username"], "rooms_deleted": len(codes)}


# ===== WebSocket =====
@api_router.websocket("/ws/{room_code}")
async def websocket_endpoint(
    websocket: WebSocket,
    room_code: str,
    token: Optional[str] = Query(default=None),
):
    room_code = room_code.upper().strip()

    if not token:
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "Token em falta", "code": "AUTH_REQUIRED"})
        await websocket.close(code=4401)
        return

    payload = decode_jwt(token)
    if not payload or "sub" not in payload:
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "Sessão inválida", "code": "AUTH_INVALID"})
        await websocket.close(code=4401)
        return

    user_id = payload["sub"]
    user = await users_col.find_one({"id": user_id}, {"_id": 0, "id": 1, "username": 1, "role": 1})
    if not user:
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "Conta não encontrada", "code": "USER_NOT_FOUND"})
        await websocket.close(code=4401)
        return

    found = await rooms_col.find_one({"code": room_code}, {"_id": 0, "code": 1})
    if not found:
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "Sala não encontrada", "code": "ROOM_NOT_FOUND"})
        await websocket.close(code=4404)
        return

    anon = anon_nickname_for(user_id, room_code)
    await room_manager.connect(websocket, room_code, anon, user_id)

    await websocket.send_json({
        "type": "joined",
        "room": room_code,
        "anon": anon,
        "participants": room_manager.participants(room_code),
        "timestamp": utc_now_iso(),
    })
    await room_manager.broadcast(room_code, {
        "type": "user_joined",
        "room": room_code,
        "anon": anon,
        "participants": room_manager.participants(room_code),
        "timestamp": utc_now_iso(),
    })

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "chat_message")

            if msg_type == "chat_message":
                body = (data.get("body") or "").strip()
                if not body:
                    continue
                body = body[:2000]
                now = utc_now()
                await messages_col.insert_one({
                    "room_code": room_code,
                    "anon": anon,
                    "user_id": user_id,
                    "body": body,
                    "created_at": now,
                })
                await room_manager.broadcast(room_code, {
                    "type": "chat_message",
                    "room": room_code,
                    "anon": anon,
                    "body": body,
                    "timestamp": now.isoformat(),
                })
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong", "timestamp": utc_now_iso()})

    except WebSocketDisconnect:
        info = room_manager.disconnect(websocket)
        if info:
            await room_manager.broadcast(room_code, {
                "type": "user_left",
                "room": room_code,
                "anon": info["anon"],
                "participants": room_manager.participants(room_code),
                "timestamp": utc_now_iso(),
            })
    except Exception as e:
        logger.exception(f"WebSocket error: {e}")
        room_manager.disconnect(websocket)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass


app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
