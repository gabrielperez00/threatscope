from fastapi import FastAPI, Request, Depends, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime
import os, io, csv

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
INGEST_TOKEN = os.getenv("THREATSCOPE_TOKEN", "letmein123")

# -------------------------------------------------------------------
# Database setup (inline, no external imports)
# -------------------------------------------------------------------
DB_URL = "sqlite:///./threatscope.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, index=True)
    host = Column(String, index=True)
    user = Column(String, index=True)
    src_ip = Column(String, index=True)
    action = Column(String, index=True)
    details = Column(Text)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, index=True)
    user = Column(String, index=True)
    host = Column(String, index=True)
    rule = Column(String, index=True)
    severity = Column(String, index=True)
    context = Column(Text)

Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------------------------------------------
# FastAPI app
# -------------------------------------------------------------------
app = FastAPI()

# Ensure dirs exist for Render
os.makedirs("app/static", exist_ok=True)
os.makedirs("app/templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.ts.desc()).limit(10).all()
    findings = db.query(Finding).order_by(Finding.ts.desc()).limit(10).all()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "events": events, "findings": findings},
    )

@app.post("/ingest_json")
async def ingest_json(payload: dict, request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token != INGEST_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        evt = Event(
            ts=datetime.fromisoformat(payload.get("ts")),
            host=payload.get("host"),
            user=payload.get("user"),
            src_ip=payload.get("src_ip"),
            action=payload.get("action"),
            details=payload.get("details"),
        )
        db.add(evt)
        db.commit()
        db.refresh(evt)
        return {"status": "ok", "id": evt.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bad payload: {e}")

@app.get("/events", response_class=JSONResponse)
def list_events(db: Session = Depends(get_db)):
    rows = db.query(Event).order_by(Event.ts.desc()).limit(100).all()
    return [
        {
            "id": e.id,
            "ts": e.ts.isoformat() if e.ts else None,
            "host": e.host,
            "user": e.user,
            "src_ip": e.src_ip,
            "action": e.action,
            "details": e.details,
        }
        for e in rows
    ]

@app.get("/events_csv")
def events_csv(db: Session = Depends(get_db)):
    rows = db.query(Event).order_by(Event.ts.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "ts", "host", "user", "src_ip", "action", "details"])
    for e in rows:
        writer.writerow([e.id, e.ts, e.host, e.user, e.src_ip, e.action, e.details])
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )

@app.get("/events_geo", response_class=JSONResponse)
def events_geo(db: Session = Depends(get_db)):
    rows = db.query(Event).filter(Event.geo_lat != None).all()
    return [
        {"lat": e.geo_lat, "lon": e.geo_lon, "user": e.user, "host": e.host, "action": e.action}
        for e in rows
    ]
