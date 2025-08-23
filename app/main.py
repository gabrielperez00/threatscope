from fastapi import FastAPI, Request, Depends, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
import os, csv, io, re, math, requests

# Config
INGEST_TOKEN = os.getenv("THREATSCOPE_TOKEN", "letmein123")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCETYPE = os.getenv("SPLUNK_SOURCETYPE", "threatscope:event")

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

app = FastAPI(title="ThreatScope")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# --------- Helpers ---------
CITY_TO_COORDS = {
    "orlando": (28.538, -81.379),
    "miami": (25.761, -80.191),
    "tampa": (27.950, -82.457),
    "jacksonville": (30.332, -81.655),
    "atlanta": (33.749, -84.388),
}
def guess_coords_from_details(details: str):
    for city, coords in CITY_TO_COORDS.items():
        if city in details.lower():
            return coords
    return None

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    p = math.pi/180
    dlat = (lat2-lat1)*p
    dlon = (lon2-lon1)*p
    a = math.sin(dlat/2)**2 + math.cos(lat1*p)*math.cos(lat2*p)*math.sin(dlon/2)**2
    return R*2*math.asin(math.sqrt(a))

# --------- Rules Engine ---------
def run_rules(db: Session):
    db.query(Finding).delete()
    db.commit()

    events = db.query(Event).order_by(Event.ts.asc()).all()
    by_user = {}

    for e in events:
        by_user.setdefault(e.user, []).append(e)

    # Off hour logins
    for e in events:
        if e.action == "login_success":
            hour = e.ts.hour
            if hour >= 22 or hour <= 5:
                db.add(Finding(ts=e.ts, user=e.user, host=e.host,
                               rule="Off hour login", severity="Medium",
                               context=f"User {e.user} logged in at {hour}:00 on {e.host}"))

    # Brute force
    for user, evs in by_user.items():
        fails = [x for x in evs if x.action == "login_fail"]
        for i in range(len(fails)):
            window = [x for x in fails if 0 <= (fails[i].ts - x.ts).total_seconds() <= 600]
            if len(window) >= 5:
                last = window[-1].ts
                succ = [x for x in evs if x.action == "login_success" and 0 <= (x.ts - last).total_seconds() <= 600]
                if succ:
                    db.add(Finding(ts=succ[0].ts, user=user, host=succ[0].host,
                                   rule="Brute force success", severity="High",
                                   context=f"{len(window)} failed logins followed by success"))
                    break

    # Suspicious PowerShell
    for e in events:
        if e.action == "powershell" and re.search(r"-enc\s+[A-Za-z0-9+/=]{20,}", e.details or "", re.I):
            db.add(Finding(ts=e.ts, user=e.user, host=e.host,
                           rule="Suspicious PowerShell encoded", severity="High", context=e.details[:200]))

    db.commit()

# --------- SPL parser ---------
def parse_spl(query: str):
    if not query:
        return []

    parts = query.split()
    filters = []
    for p in parts:
        if "=" in p:
            k,v = p.split("=",1)
            k,v = k.lower(), v.strip('"').strip("'")
            if k=="user":   filters.append(lambda q,v=v: q.filter(Event.user.like(v.replace("*","%"))))
            elif k=="host": filters.append(lambda q,v=v: q.filter(Event.host.like(v.replace("*","%"))))
            elif k in ("src","src_ip"): filters.append(lambda q,v=v: q.filter(Event.src_ip.like(v.replace("*","%"))))
            elif k=="action": filters.append(lambda q,v=v: q.filter(Event.action.like(v.replace("*","%"))))
            else: filters.append(lambda q,v=v: q.filter(Event.details.like(f"%{v}%")))
        else:
            filters.append(lambda q,p=p: q.filter(Event.details.like(f"%{p}%")))
    return filters

# --------- Routes ---------
@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    total_findings = db.query(Finding).count()
    latest = db.query(Finding).order_by(Finding.ts.desc()).limit(10).all()
    return templates.TemplateResponse("index.html", {
        "request": request, "total_events": total_events,
        "total_findings": total_findings, "latest": latest
    })

@app.get("/hunt", response_class=HTMLResponse)
def hunt(request: Request, q: str = "", user: str = "", host: str = "", spl: str = "", db: Session = Depends(get_db)):
    return templates.TemplateResponse("hunt.html", {
        "request": request, "q": q, "user": user, "host": host, "spl": spl
    })

@app.get("/hunt_table", response_class=HTMLResponse)
def hunt_table(request: Request, q: str = "", user: str = "", host: str = "", spl: str = "", page: int = 1, page_size: int = 50, db: Session = Depends(get_db)):
    qry = db.query(Event)
    if q:    qry = qry.filter(Event.details.like(f"%{q}%"))
    if user: qry = qry.filter(Event.user == user)
    if host: qry = qry.filter(Event.host == host)
    for f in parse_spl(spl): qry = f(qry)

    total = qry.count()
    rows = qry.order_by(Event.ts.desc()).offset((page-1)*page_size).limit(page_size).all()
    return templates.TemplateResponse("hunt_table.html", {
        "request": request, "rows": rows, "q": q, "user": user, "host": host,
        "spl": spl, "page": page, "page_size": page_size, "total": total
    })

@app.post("/ingest_json")
async def ingest_json(payload: dict, request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("X-TS-Token")
    if token != INGEST_TOKEN:
        raise HTTPException(status_code=401, detail="bad token")
    ts = datetime.fromisoformat(payload["ts"])
    e = Event(ts=ts, host=payload.get("host",""), user=payload.get("user",""),
              src_ip=payload.get("src_ip",""), action=payload.get("action",""), details=payload.get("details",""))
    coords = guess_coords_from_details(e.details or "")
    if coords: e.geo_lat, e.geo_lon = coords
    db.add(e); db.commit(); run_rules(db)
    return {"status":"ok"}

@app.get("/findings")
def api_findings(db: Session = Depends(get_db)):
    return [{"_time": f.ts.isoformat(), "user": f.user, "host": f.host, "rule": f.rule,
             "severity": f.severity, "message": f.context, "src": None} 
            for f in db.query(Finding).order_by(Finding.ts.desc()).all()]

@app.post("/export_to_splunk")
def export_to_splunk(limit: int = 200, db: Session = Depends(get_db)):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        raise HTTPException(status_code=400, detail="SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN not set")
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}", "Content-Type":"application/json"}
    events = db.query(Event).order_by(Event.ts.desc()).limit(limit).all()
    findings = db.query(Finding).order_by(Finding.ts.desc()).limit(limit).all()

    batch = []
    for e in events:
        batch.append({"time": int(e.ts.timestamp()), "host": e.host, "sourcetype": SPLUNK_SOURCETYPE, "index": SPLUNK_INDEX,
                      "event": {"_time": e.ts.isoformat(), "user": e.user, "host": e.host, "src": e.src_ip, "action": e.action, "message": e.details}})
    for f in findings:
        batch.append({"time": int(f.ts.timestamp()), "host": f.host, "sourcetype": "threatscope:finding", "index": SPLUNK_INDEX,
                      "event": {"_time": f.ts.isoformat(), "user": f.user, "host": f.host, "action": f.rule, "severity": f.severity, "message": f.context}})

    ok, failed = 0,0
    for b in batch:
        r = requests.post(SPLUNK_HEC_URL, headers=headers, json=b, timeout=5)
        if r.status_code==200 and r.json().get("code")==0: ok+=1
        else: failed+=1
    return {"sent":ok, "failed":failed}
