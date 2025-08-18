from fastapi import FastAPI, Request, Depends, UploadFile
from fastapi.responses import StreamingResponse
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
from sqlalchemy import func
from fastapi import HTTPException
import os
INGEST_TOKEN = os.getenv("THREATSCOPE_TOKEN", "letmein123")

import csv, io, re, math

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
    action = Column(String, index=True)             # login_success, login_fail, powershell, file_write, network_conn
    details = Column(Text)                           # free text for message
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, index=True)
    user = Column(String, index=True)
    host = Column(String, index=True)
    rule = Column(String, index=True)
    severity = Column(String, index=True)            # Low, Medium, High
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

# simple geo lookup stub to enable impossible travel demo
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

# rules
def run_rules(db: Session):
    db.query(Finding).delete()  # rebuild findings for simplicity
    db.commit()

    events = db.query(Event).order_by(Event.ts.asc()).all()

    # 1 off hour login success between 22 and 5
    for e in events:
        if e.action == "login_success":
            hour = e.ts.hour
            if hour >= 22 or hour <= 5:
                f = Finding(ts=e.ts, user=e.user, host=e.host,
                            rule="Off hour login",
                            severity="Medium",
                            context=f"User {e.user} logged in at {hour}:00 on {e.host}")
                db.add(f)

    # 2 brute force pattern 5 or more fails in 10 minutes followed by success
    by_user = {}
    for e in events:
        by_user.setdefault(e.user, []).append(e)
    for user, evs in by_user.items():
        fails = [x for x in evs if x.action == "login_fail"]
        for i in range(len(fails)):
            window = [x for x in fails if 0 <= (fails[i].ts - x.ts).total_seconds() <= 600]
            if len(window) >= 5:
                # success within 10 minutes after last fail
                last = window[-1].ts
                succ = [x for x in evs if x.action == "login_success" and 0 <= (x.ts - last).total_seconds() <= 600]
                if succ:
                    db.add(Finding(ts=succ[0].ts, user=user, host=succ[0].host,
                                   rule="Brute force success",
                                   severity="High",
                                   context=f"{len(window)} failed logins followed by success"))
                    break

    # 3 suspicious powershell with base64 flag
    for e in events:
        if e.action == "powershell" and re.search(r"-enc\s+[A-Za-z0-9+/=]{20,}", e.details or "", re.IGNORECASE):
            db.add(Finding(ts=e.ts, user=e.user, host=e.host,
                           rule="Suspicious PowerShell encoded",
                           severity="High",
                           context=e.details[:200]))

    # 4 impossible travel based on naive city hints in details within 60 minutes and distance over 800 km
    by_user_sorted = {u: sorted(v, key=lambda x: x.ts) for u, v in by_user.items()}
    for user, evs in by_user_sorted.items():
        last_loc = None
        last_time = None
        for e in evs:
            loc = guess_coords_from_details(e.details or "")
            if loc and last_loc and last_time:
                dt = (e.ts - last_time).total_seconds() / 3600.0
                dist = haversine(last_loc[0], last_loc[1], loc[0], loc[1])
                if dt <= 1.0 and dist >= 800:
                    db.add(Finding(ts=e.ts, user=user, host=e.host,
                                   rule="Impossible travel",
                                   severity="High",
                                   context=f"Distance {int(dist)} km in {dt:.1f} hours"))
    # 5 lateral movement: same user logs into multiple hosts within 15 minutes
    for user, evs in by_user_sorted.items():
        for i in range(len(evs)):
            for j in range(i+1, len(evs)):
                if evs[i].action == "login_success" and evs[j].action == "login_success":
                    if evs[i].host != evs[j].host:
                        dt = abs((evs[j].ts - evs[i].ts).total_seconds())
                        if dt <= 900:  # 15 min
                            db.add(Finding(ts=evs[j].ts, user=user, host=evs[j].host,
                                           rule="Lateral movement",
                                           severity="High",
                                           context=f"{user} logged into {evs[i].host} and {evs[j].host} within {dt/60:.1f} minutes"))
                            break

            if loc:
                last_loc = loc
                last_time = e.ts

    db.commit()

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    total_findings = db.query(Finding).count()
    latest = db.query(Finding).order_by(Finding.ts.desc()).limit(10).all()
    return templates.TemplateResponse("index.html",
                                      {"request": request,
                                       "total_events": total_events,
                                       "total_findings": total_findings,
                                       "latest": latest})

@app.get("/hunt", response_class=HTMLResponse)
def hunt(request: Request, q: str = "", user: str = "", host: str = "", db: Session = Depends(get_db)):
    qry = db.query(Event)
    if q:
        like = f"%{q}%"
        qry = qry.filter(Event.details.like(like))
    if user:
        qry = qry.filter(Event.user == user)
    if host:
        qry = qry.filter(Event.host == host)
    rows = qry.order_by(Event.ts.desc()).limit(500).all()
    return templates.TemplateResponse("hunt.html",
                                      {"request": request, "rows": rows, "q": q, "user": user, "host": host})

@app.post("/ingest_json")
async def ingest_json(payload: dict, request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("X-TS-Token")
    if token != INGEST_TOKEN:
        raise HTTPException(status_code=401, detail="bad token")

    try:
        ts = datetime.fromisoformat(payload["ts"])
    except Exception:
        raise HTTPException(status_code=400, detail="bad ts format, expected ISO 8601")

    e = Event(
        ts=ts,
        host=payload.get("host",""),
        user=payload.get("user",""),
        src_ip=payload.get("src_ip",""),
        action=payload.get("action",""),
        details=payload.get("details","")
    )
    coords = guess_coords_from_details(e.details or "")
    if coords:
        e.geo_lat, e.geo_lon = coords

    db.add(e)
    db.commit()
    run_rules(db)
    return {"status":"ok"}

@app.get("/hunt_table", response_class=HTMLResponse)
def hunt_table(request: Request, q: str = "", user: str = "", host: str = "", db: Session = Depends(get_db)):
    qry = db.query(Event)
    if q:
        qry = qry.filter(Event.details.like(f"%{q}%"))
    if user:
        qry = qry.filter(Event.user == user)
    if host:
        qry = qry.filter(Event.host == host)
    rows = qry.order_by(Event.ts.desc()).limit(500).all()
    return templates.TemplateResponse("hunt_table.html",
                                      {"request": request, "rows": rows, "q": q, "user": user, "host": host})

@app.post("/seed_demo")
def seed_demo(db: Session = Depends(get_db)):
    db.query(Event).delete()
    db.query(Finding).delete()
    now = datetime.utcnow().replace(microsecond=0)

    demo = [
        # brute force then success
        {"ts": now - timedelta(minutes=30), "host":"win10-01", "user":"alex", "src_ip":"10.0.0.10", "action":"login_fail", "details":"invalid password"},
        {"ts": now - timedelta(minutes=29), "host":"win10-01", "user":"alex", "src_ip":"10.0.0.10", "action":"login_fail", "details":"invalid password"},
        {"ts": now - timedelta(minutes=28), "host":"win10-01", "user":"alex", "src_ip":"10.0.0.10", "action":"login_fail", "details":"invalid password"},
        {"ts": now - timedelta(minutes=27), "host":"win10-01", "user":"alex", "src_ip":"10.0.0.10", "action":"login_fail", "details":"invalid password"},
        {"ts": now - timedelta(minutes=26), "host":"win10-01", "user":"alex", "src_ip":"10.0.0.10", "action":"login_fail", "details":"invalid password"},
        {"ts": now - timedelta(minutes=24), "host":"win10-01", "user":"alex", "src_ip":"10.0.0.10", "action":"login_success", "details":"interactive logon"},
        # off hour success
        {"ts": now.replace(hour=2, minute=5, second=0), "host":"srv-ad-01", "user":"pat", "src_ip":"10.0.1.5", "action":"login_success", "details":"domain admin logon"},
        # encoded powershell
        {"ts": now - timedelta(minutes=3), "host":"win11-02", "user":"jordan", "src_ip":"10.0.2.55", "action":"powershell", "details":"powershell -enc SQBFAFgAIAAvQwA6AFwA"},
        # impossible travel hint
        {"ts": now - timedelta(minutes=50), "host":"laptop-03", "user":"sam", "src_ip":"100.100.100.10", "action":"login_success", "details":"successful login from Orlando"},
        {"ts": now - timedelta(minutes=10), "host":"laptop-03", "user":"sam", "src_ip":"100.100.100.11", "action":"login_success", "details":"successful login from Miami"},
    ]
    for r in demo:
        ev = Event(**r)
        coords = guess_coords_from_details(ev.details or "")
        if coords:
            ev.geo_lat, ev.geo_lon = coords
        db.add(ev)
    db.commit()
    run_rules(db)
    return RedirectResponse(url="/", status_code=303)

@app.get("/findings")
def api_findings(db: Session = Depends(get_db)):
    out = []
    for f in db.query(Finding).order_by(Finding.ts.desc()).all():
        out.append({
            "ts": f.ts.isoformat(),
            "user": f.user,
            "host": f.host,
            "rule": f.rule,
            "severity": f.severity,
            "context": f.context
        })
    return out


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    rows = db.query(Finding.rule, func.count(Finding.id)).group_by(Finding.rule).all()
    return {"by_rule": [{"rule": r, "count": c} for r, c in rows]}
@app.get("/hunt_table", response_class=HTMLResponse)
def hunt_table(request: Request, q: str = "", user: str = "", host: str = "", db: Session = Depends(get_db)):
    qry = db.query(Event)
    if q:
        qry = qry.filter(Event.details.like(f"%{q}%"))
    if user:
        qry = qry.filter(Event.user == user)
    if host:
        qry = qry.filter(Event.host == host)
    rows = qry.order_by(Event.ts.desc()).limit(500).all()
    return templates.TemplateResponse("hunt_table.html",
                                      {"request": request, "rows": rows, "q": q, "user": user, "host": host})

@app.get("/export_findings.csv")
def export_findings(db: Session = Depends(get_db)):
    rows = db.query(Finding).order_by(Finding.ts.asc()).all()

    def gen():
        yield "ts,user,host,rule,severity,context\r\n"
        for f in rows:
            ctx = (f.context or "").replace('"', "'")
            yield f'{f.ts.isoformat()},{f.user},{f.host},{f.rule},{f.severity},"{ctx}"\r\n'

    return StreamingResponse(
        gen(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"}
    )

@app.get("/map", response_class=HTMLResponse)
def map_view(request: Request):
    return templates.TemplateResponse("map.html", {"request": request})
