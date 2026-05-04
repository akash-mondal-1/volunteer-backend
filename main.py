from dotenv import load_dotenv
load_dotenv()


from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from functools import lru_cache
import os
import sqlite3
import time

request_counts = {}
import bcrypt
import jwt
from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

# ===== CONFIG =====
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

DATABASE_PATH = os.getenv("DATABASE_PATH", "./volunteer.db")
app = FastAPI(title="Volunteer API")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ===== MODELS =====
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class NeedCreate(BaseModel):
    title: str = Field(max_length=200)
    location: str = Field(max_length=200)
    category: str = Field(max_length=50)
    urgency: int = Field(ge=1, le=5)
    description: str = Field(max_length=1000)

class Need(BaseModel):
    id: int
    title: str
    location: str
    category: str
    urgency: int
    description: str
    created_at: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ===== DB =====
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@lru_cache()
def init_db():
    with get_db() as conn:
        # Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Needs table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS needs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                category TEXT NOT NULL,
                urgency INTEGER NOT NULL CHECK (urgency BETWEEN 1 and 5),
                description TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        # Indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_needs_user_id ON needs(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_needs_urgency ON needs(urgency)")
        conn.commit()

init_db()

# ===== HELPERS =====
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hash_: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hash_.encode('utf-8'))

def create_token(user_id: int) -> str:
    return jwt.encode(
        {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(hours=24)},
        JWT_SECRET,
        algorithm="HS256"
    )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        user_id = int(payload["sub"])
        return {"id": user_id}
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

def infer_category(text: str) -> str:
    text = text.lower()

    mapping = {
        "food": ["food", "hungry", "meal", "ration", "eat"],
        "medical": ["medical", "doctor", "hospital", "blood", "injury", "medicine"],
        "shelter": ["home", "shelter", "house", "stay", "roof"],
        "clothing": ["clothes", "dress", "jacket", "blanket"],
        "rescue": ["rescue", "help", "stuck", "trapped", "flood"]
    }

    scores = {}

    for category, keywords in mapping.items():
        score = sum(1 for word in keywords if word in text)
        scores[category] = score

    best = max(scores, key=scores.get)

    return best if scores[best] > 0 else "other"

def row_to_need(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "location": row["location"],
        "category": row["category"],
        "urgency": row["urgency"],
        "description": row["description"],
        "created_at": row["created_at"]
    }

# ===== AUTH ROUTES =====
@app.post("/auth/signup", response_model=Token)
def signup(user: UserCreate):
    try:
        with get_db() as conn:
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (user.email,)).fetchone()
            if existing:
                raise HTTPException(400, detail="Email already registered")
            
            password_hash = hash_password(user.password)
            cursor = conn.execute(
                """
                INSERT INTO users (
                    email,
                    password_hash,
                    role,
                    created_at,
                    last_password_change
                )
                VALUES (
                    ?, ?, 'user', datetime('now'), datetime('now')
                )
                """,
                (user.email, password_hash)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            token = create_token(user_id)
            return {"access_token": token, "token_type": "bearer"}
    except Exception as e:
        import traceback
        print("SIGNUP ERROR:", str(e))
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/login", response_model=Token)
def login(user: UserLogin):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE email = ?", 
            (user.email,)
        ).fetchone()
        
        if not row or not verify_password(user.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_token(row["id"])
        return {"access_token": token, "token_type": "bearer"}

# ===== NEEDS ROUTES =====
@app.get("/", tags=["health"])
def health():
    return {"status": "ok"}

@app.get("/needs", response_model=List[Dict[str, Any]])
def get_needs():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, title, location, category, urgency, description, created_at FROM needs ORDER BY urgency DESC, created_at DESC"
        ).fetchall()
        return [row_to_need(row) for row in rows]

@app.post("/needs", response_model=Dict[str, Any])
def create_need(
    need: NeedCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_id = current_user["id"]
    
    text = need.description.lower()
    
    # Category detection
    if not need.category:
        if "food" in text:
            need.category = "food"
        elif "medical" in text or "doctor" in text:
            need.category = "medical"
        elif "shelter" in text or "house" in text:
            need.category = "shelter"
        elif "education" in text or "school" in text:
            need.category = "education"
    
    # Urgency detection
    if not need.urgency or need.urgency == 1:
        if "urgent" in text or "immediately" in text:
            need.urgency = 5
        elif "soon" in text:
            need.urgency = 4
    
# Strict validation
    if not need.title or len(need.title.strip()) < 3:
        raise HTTPException(400, "Title must be at least 3 characters")
    if len(need.title) > 100:
        raise HTTPException(400, "Title too long")
    if not need.location or len(need.location.strip()) < 2:
        raise HTTPException(400, "Location required")
    if need.urgency < 1 or need.urgency > 5:
        raise HTTPException(400, "Urgency must be between 1 and 5")
    if len(need.description) > 500:
        raise HTTPException(400, "Description too long")

    # Rate limiting (5/min per user)
    user_id = str(current_user["id"])
    now = time.time()
    if user_id not in request_counts:
        request_counts[user_id] = []
    # keep only last 60 seconds
    request_counts[user_id] = [
        t for t in request_counts[user_id] if now - t < 60
    ]
    if len(request_counts[user_id]) >= 5:
        raise HTTPException(429, "Too many requests")
    request_counts[user_id].append(now)
    
    # Auto-category inference
    if not need.category or need.category.strip() == "":
        combined_text = f"{need.title} {need.description}"
        need.category = infer_category(combined_text)
    
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO needs (
                title,
                location,
                category,
                urgency,
                description,
                user_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                need.title,
                need.location,
                need.category,
                need.urgency,
                need.description,
                user_id,
            ),
        )
        conn.commit()
        new_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM needs WHERE id = ?", (new_id,)).fetchone()
        return row_to_need(row)

@app.get("/my-needs", response_model=List[Dict[str, Any]])
def get_my_needs(current_user: Dict[str, Any] = Depends(get_current_user)):
    user_id = current_user["id"]
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, title, location, category, urgency, description, created_at FROM needs WHERE user_id = ? ORDER BY urgency DESC, created_at DESC",
            (user_id,)
        ).fetchall()
        return [row_to_need(row) for row in rows]

@app.put("/needs/{need_id}", response_model=Dict[str, Any])
def update_need(
    need_id: int,
    need: NeedCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_id = current_user["id"]
    with get_db() as conn:
        # Check owner
        row = conn.execute("SELECT user_id FROM needs WHERE id = ?", (need_id,)).fetchone()
        if not row or row["user_id"] != user_id:
            raise HTTPException(403, detail="Not authorized")
        
        conn.execute(
            """
            UPDATE needs SET title = ?, location = ?, category = ?, urgency = ?, description = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                need.title,
                need.location,
                need.category,
                need.urgency,
                need.description,
                need_id,
                user_id,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM needs WHERE id = ?", (need_id,)).fetchone()
        return row_to_need(row)

@app.delete("/needs/{need_id}", status_code=204)
def delete_need(
    need_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    user_id = current_user["id"]
    with get_db() as conn:
        row = conn.execute("SELECT user_id FROM needs WHERE id = ?", (need_id,)).fetchone()
        if not row or row["user_id"] != user_id:
            raise HTTPException(403, detail="Not authorized")
        
        conn.execute("DELETE FROM needs WHERE id = ? AND user_id = ?", (need_id, user_id))
        conn.commit()

# ===== MATCHING =====
@app.get("/match")
def match_needs(skills: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user)):
    words = skills.lower().split()
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM needs").fetchall()
        
        matches = []
        for row in rows:
            need = row_to_need(row)
            score = need["urgency"] * 10
            reasons = [f"Urgency {need['urgency']}/5"]
            
            if any(word in need["category"].lower() for word in words):
                score += 30
                reasons.append("Category match")
            
            if any(word in need["description"].lower() for word in words):
                score += 20
                reasons.append("Keyword match")
            
            matches.append({
                **need,
                "score": score,
                "reason": "; ".join(reasons)
            })
        
        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches[:3]
