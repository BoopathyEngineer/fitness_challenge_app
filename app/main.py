from fastapi import FastAPI, HTTPException, Depends, status, Path, Body, Form, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from mangum import Mangum
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, date
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, String, Integer, Date, ForeignKey, and_
from sqlalchemy.orm import sessionmaker, declarative_base, Session

DATABASE_URL = "postgresql://boopathy:Admin123!@3.85.229.31/fitness_details"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

SECRET_KEY = "a30ca6b675a0f3654deefacfeb25f270d9b74ec498cf6c35bb52931f6a89925d"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database Models
class Member(Base):
    __tablename__ = "members"
    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String)
    email = Column(String, unique=True)
    name = Column(String)
    password = Column(String)
    points = Column(Integer, default=0)
    role = Column(String)  # 'admin' or 'user'

class Challenge(Base):
    __tablename__ = "challenges"
    id = Column(String, primary_key=True)
    description = Column(String)
    points = Column(Integer)
    challenge_date = Column(Date)

class CompletedChallenge(Base):
    __tablename__ = "completed_challenges"
    id = Column(Integer, primary_key=True, index=True)
    member_id = Column(Integer, ForeignKey("members.id"))
    challenge_id = Column(String, ForeignKey("challenges.id"))
    completed_at = Column(Date, default=date.today)

Base.metadata.create_all(bind=engine)

class MemberCreate(BaseModel):
    phone: str
    email: EmailStr
    name: str
    password: str
    role: str 

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class ChallengeCreate(BaseModel):
    id: str
    description: str
    points: int
    challenge_date: date

class ChallengeUpdate(BaseModel):
    description: str
    points: int
    challenge_date: date

# Utility Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_member(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        member_id = payload.get("sub")
        member = db.query(Member).filter(Member.id == int(member_id)).first()
        if member is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return member
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        member_id = payload.get("sub")
        member = db.query(Member).filter(Member.id == int(member_id)).first()
        if member is None or member.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
        return member
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)}
    )

@app.post("/register/user")
def register_user(member: MemberCreate, db: Session = Depends(get_db)):
    if member.role != "user":
        raise HTTPException(status_code=400, detail="Role must be 'user'")
    db_member = Member(
        phone=member.phone,
        email=member.email,
        name=member.name,
        password=get_password_hash(member.password),
        points=0,
        role=member.role
    )
    db.add(db_member)
    db.commit()
    db.refresh(db_member)
    return {"member_id": db_member.id, "status": "user registered"}

@app.post("/register/admin")
def register_admin(member: MemberCreate, db: Session = Depends(get_db)):
    if member.role != "admin":
        raise HTTPException(status_code=400, detail="Role must be 'admin'")
    db_member = Member(
        phone=member.phone,
        email=member.email,
        name=member.name,
        password=get_password_hash(member.password),
        points=0,
        role=member.role
    )
    db.add(db_member)
    db.commit()
    db.refresh(db_member)
    return {"member_id": db_member.id, "status": "admin registered"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    member = db.query(Member).filter(Member.email == form_data.username).first()
    if not member or not verify_password(form_data.password, member.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token({"sub": str(member.id)}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_access_token({"sub": str(member.id)}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get("/challenges/today")
def get_today_challenges(db: Session = Depends(get_db)):
    challenges = db.query(Challenge).filter(Challenge.challenge_date == date.today()).all()
    return challenges


@app.post("/challenges/attempt")
def attempt_challenge(
    challenge_id: str = Form(...),
    current_member: Member = Depends(get_current_member),
    db: Session = Depends(get_db)
):
    challenge = db.query(Challenge).filter(
        and_(
            Challenge.id == challenge_id,
            Challenge.challenge_date == date.today()
        )
    ).first()

    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    already_completed = db.query(CompletedChallenge).filter_by(
        member_id=current_member.id,
        challenge_id=challenge.id
    ).first()

    if already_completed:
        return {"status": "already completed", "challenge_id": challenge_id}

    completed = CompletedChallenge(member_id=current_member.id, challenge_id=challenge.id)
    current_member.points += challenge.points
    db.add(completed)
    db.commit()

    return {"status": "completed", "earned_points": challenge.points}

@app.get("/profile")
def get_profile(current_member: Member = Depends(get_current_member), db: Session = Depends(get_db)):
    completed_challenges = db.query(CompletedChallenge).filter_by(member_id=current_member.id).count()
    return {"name": current_member.name, "points": current_member.points, "completed_challenges": completed_challenges}

@app.get("/leaderboard")
def leaderboard(db: Session = Depends(get_db)):
    results = (
        db.query(
            Member.name.label("user_name"),
            Challenge.id.label("challenge_id"),
            Challenge.description.label("challenge_name"),
            Challenge.points
        )
        .join(CompletedChallenge, Member.id == CompletedChallenge.member_id)
        .join(Challenge, Challenge.id == CompletedChallenge.challenge_id)
        .order_by(Member.points.desc())
        .limit(10)
        .all()
    )

    leaderboard_data = [
        {
            "user_name": row.user_name,
            "challenge_id": row.challenge_id,
            "challenge_name": row.challenge_name,
            "points": row.points
        }
        for row in results
    ]
    return leaderboard_data
@app.post("/admin/challenge")
def create_challenge(
    id: str = Form(...),
    description: str = Form(...),
    points: int = Form(...),
    challenge_date: date = Form(...),
    db: Session = Depends(get_db),
    current_admin: Member = Depends(get_current_admin)
):
    db_challenge = Challenge(id=id, description=description, points=points, challenge_date=challenge_date)
    db.add(db_challenge)
    db.commit()
    return {"status": "Challenge created", "challenge_id": db_challenge.id}

@app.get("/admin/challenge")
def read_challenge(challenge_id: str = Query(...), db: Session = Depends(get_db)):
    challenge = db.query(Challenge).filter_by(id=challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return challenge

@app.put("/admin/challenge")
def update_challenge(
    challenge_id: str = Form(...),
    description: str = Form(...),
    points: int = Form(...),
    challenge_date: date = Form(...),
    db: Session = Depends(get_db),
    current_admin: Member = Depends(get_current_admin)
):
    challenge = db.query(Challenge).filter_by(id=challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    challenge.description = description
    challenge.points = points
    challenge.challenge_date = challenge_date

    db.commit()
    return {"status": "Challenge updated", "challenge_id": challenge_id}

@app.delete("/admin/challenge/{challenge_id}")
def delete_challenge(challenge_id: str, db: Session = Depends(get_db)):
    challenge = db.query(Challenge).filter_by(id=challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    db.delete(challenge)
    db.commit()
    return {"status": "Challenge deleted", "challenge_id": challenge_id}

handler = Mangum(app)
