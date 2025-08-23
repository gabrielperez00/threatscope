from fastapi import FastAPI, Request, Depends, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from datetime import datetime, timedelta
import os, csv, io, re, math, requests
SPLUNK_URL = "https://prd-p-v8lb6.splunkcloud.com:8088/services/collector"
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "dfc55283-b21b-4a4d-86fb-841688ef94f0")

# ---------------- Config ----------------
INGEST_TOKEN = os.getenv("THREATSCOPE_TOKEN", "letmein123")

# Optional Splunk HEC (leave empty if you’re not using it yet)
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "main")
SPLUNK_SOURCETYPE = os.getenv("SPLUNK_SOURCETYPE", "threatscope:event")

DB_URL = "sqlite:///./threatscope.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ---------------- Models ----------------
class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, index=True)
    host = Column(String, index=True)
    user = Column(String, index=True)
    src_ip = Column(String, index=True)
    action = Column(String, index=True)   # login_success, login_fail, powershell, ...
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
    severity = Column(String, index=True)  # Low, Medium, High
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

# ---------------- Helpers ----------------
CITY_TO_COORDS = {
    "orlando": (28.538, -81.379),
    "miami": (25.761, -80.191),
    "tampa": (27.950, -82.457),
    "jacksonville": (30.332, -81.655),
    "atlanta": (33.749, -84.388),
}

def guess_coords_from_details(details: str):
    for city, coords in CITY_TO_COORDS.items():
        if city in (details or "").lower():
            return coords
    return None

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    p = math.pi/180
    dlat = (lat2-lat1)*p
    dlon = (lon2-lon1)*p
    a = math.sin(dlat/2)**2 + math.cos(lat1*p)*math.cos(lat2*p)*math.sin(dlon/2)**2
    return R*2*math.asin(math.sqrt(a))

# ---------------- Rules Engine ----------------
def run_rules(db: Session):
    db.query(Finding).delete()
    db.commit()

    events = db.query(Event).order_by(Event.ts.asc()).all()
    by_user = {}
    for e in events:
        by_user.setdefault(e.user, []).append(e)

    # 1) Off-hour login success (22:00–05:59)
    for e in events:
        if e.action == "login_success" and e.ts:
            hour = e.ts.hour
            if hour >= 22 or hour <= 5:
                db.add(Finding(
                    ts=e.ts, user=e.user, host=e.host,
                    rule="Off hour login",
                    severity="Medium",
                    context=f"User {e.user} logged in at {hour:02d}:00 on {e.host}"
                ))

    # 2) Brute force: ≥5 fails in 10m then success within 10m
    for user, evs in by_user.items():
        fails = [x for x in evs if x.action == "login_fail"]
        for i in range(len(fails)):
            window = [x for x in fails if 0 <= (fails[i].ts - x.ts).total_seconds() <= 600]
            if len(window) >= 5:
                last = window[-1].ts
                succ = [x for x in evs if x.action == "login_success" and 0 <= (x.ts - last).total_seconds() <= 600]
                if succ:
                    db.add(Finding(
                        ts=succ[0].ts, user=user, host=succ[0].host,
                        rule="Brute force success",
                        severity="High",
                        context=f"{len(window)} failed logins followed by success"
                    ))
                    break

    # 3) Suspicious PowerShell (encoded)
    for e in events:
        if e.action == "powershell" and re.search(r"-enc\s+[A-Za-z0-9+/=]{20,}", e.details or "", re.I):
            db.add(Finding(
                ts=e.ts, user=e.user, host=e.host,
                rule="Suspicious PowerShell encoded",
                severity="High",
                context=(e.details or "")[:200]
            ))

    db.commit()

# ---------------- SPL-like parser (simple) ----------------
def parse_spl(query: str):
    if not query:
        return []
    parts = query.split()
    filters = []
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            k = k.lower().strip()
            v = v.strip().strip('"').strip("'")
            v_like = v.replace("*", "%")
            if k == "user":
                filters.append(lambda q, v=v_like: q.filter(Event.user.like(v)))
            elif k == "host":
                filters.append(lambda q, v=v_like: q.filter(Event.host.like(v)))
            elif k in ("src", "src_ip", "ip"):
                filters.append(lambda q, v=v_like: q.filter(Event.src_ip.like(v)))
            elif k == "action":
                filters.append(lambda q, v=v_like: q.filter(Event.action.like(v)))
            elif k in ("details", "message", "msg"):
                filters.append(lambda q, v=v_like: q.filter(Event.details.like(v)))
            else:
                filters.append(lambda q, v=v_like: q.filter(Event.details.like(v)))
        else:
            filters.append(lambda q, w=p: q.filter(Event.details.like(f"%{w}%")))
    return filters

# ---------------- Routes ----------------
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    total_findings = db.query(Finding).count()
    latest = db.query(Finding).order_by(Finding.ts.desc()).limit(10).all()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_events": total_events,
        "total_findings": total_findings,
        "latest": latest
    })

@app.get("/hunt", response_class=HTMLResponse)
def hunt(request: Request, q: str = "", user: str = "", host: str = "", spl: str = "", db: Session = Depends(get_db)):
    return templates.TemplateResponse("hunt.html", {
        "request": request,
        "q": q, "user": user, "host": host, "spl": spl
    })

@app.get("/hunt_table", response_class=HTMLResponse)
def hunt_table(
    request: Request,
    q: str = "",
    user: str = "",
    host: str = "",
    spl: str = "",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db)
):
    page = max(1, page)
    page_size = max(1, min(page_size, 200))

    qry = db.query(Event)
    if q:    qry = qry.filter(Event.details.like(f"%{q}%"))
    if user: qry = qry.filter(Event.user == user)
    if host: qry = qry.filter(Event.host == host)
    for f in parse_spl(spl):
        qry = f(qry)

    total = qry.count()
    rows = qry.order_by(Event.ts.desc()).offset((page-1)*page_size).limit(page_size).all()

    return templates.TemplateResponse("hunt_table.html", {
        "request": request,
        "rows": rows, "q": q, "user": user, "host": host,
        "spl": spl, "page": page, "page_size": page_size, "total": total
    })

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

        # off-hour success
        {"ts": now.replace(hour=2, minute=5, second=0), "host":"srv-ad-01", "user":"pat", "src_ip":"10.0.1.5", "action":"login_success", "details":"domain admin logon"},

        # encoded powershell
        {"ts": now - timedelta(minutes=3), "host":"win11-02", "user":"jordan", "src_ip":"10.0.2.55", "action":"powershell", "details":"powershell -enc SQBFAFgAIAAvQwA6AFwA"},

        # impossible travel hints
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
            "_time": f.ts.isoformat(),
            "user": f.user,
            "host": f.host,
            "rule": f.rule,
            "severity": f.severity,
            "message": f.context,
            "src": None
        })
    return out

@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    rows = db.query(Finding.rule, func.count(Finding.id)).group_by(Finding.rule).all()
    return {"by_rule": [{"rule": r, "count": c} for r, c in rows]}

@app.get("/export_events.csv")
def export_events(db: Session = Depends(get_db)):
    rows = db.query(Event).order_by(Event.ts.asc()).all()
    def gen():
        yield "ts,host,user,src_ip,action,details,geo_lat,geo_lon\r\n"
        for e in rows:
            details = (e.details or "").replace('"', "'").replace("\r", " ").replace("\n", " ")
            ts = e.ts.isoformat() if e.ts else ""
            lat = "" if e.geo_lat is None else e.geo_lat
            lon = "" if e.geo_lon is None else e.geo_lon
            yield f'{ts},{e.host},{e.user},{e.src_ip},{e.action},"{details}",{lat},{lon}\r\n'
    return StreamingResponse(
        gen(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"}
    )

@app.get("/export_findings.csv")
def export_findings(db: Session = Depends(get_db)):
    # Query all findings oldest→newest for stable CSVs
    rows = db.query(Finding).order_by(Finding.ts.asc()).all()

    def gen():
        # header
        yield "ts,user,host,rule,severity,context\r\n"
        for f in rows:
            # sanitize context for CSV (no raw quotes/newlines)
            ctx = (f.context or "").replace('"', "'").replace("\r", " ").replace("\n", " ")
            ts = f.ts.isoformat() if f.ts else ""
            yield f'{ts},{f.user},{f.host},{f.rule},{f.severity},"{ctx}"\r\n'

    return StreamingResponse(
        gen(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"}
    )

@app.get("/events_geo")
def events_geo(db: Session = Depends(get_db)):
    rows = db.query(Event).filter(Event.geo_lat != None, Event.geo_lon != None).all()
    return [
        {
            "ts": e.ts.isoformat(),
            "user": e.user,
            "host": e.host,
            "src_ip": e.src_ip,
            "action": e.action,
            "details": e.details,
            "lat": e.geo_lat,
            "lon": e.geo_lon,
        }
        for e in rows
    ]
@app.get("/map", response_class=HTMLResponse)
def map_view(request: Request):
    return templates.TemplateResponse("map.html", {"request": request})

@app.get("/events_geo")
def events_geo(db: Session = Depends(get_db)):
    rows = db.query(Event).filter(Event.geo_lat.isnot(None), Event.geo_lon.isnot(None))\
            .order_by(Event.ts.desc()).limit(1000).all()
    return [
        {
            "ts": r.ts.isoformat(),
            "host": r.host, "user": r.user, "src_ip": r.src_ip,
            "action": r.action, "details": r.details,
            "lat": r.geo_lat, "lon": r.geo_lon
        }
        for r in rows
    ]

# Optional: Export to Splunk (safe if env vars are blank)
def _as_splunk_event(e: Event):
    return {
        "time": int(e.ts.timestamp()) if e.ts else int(datetime.utcnow().timestamp()),
        "host": e.host,
        "source": "threatscope",
        "sourcetype": SPLUNK_SOURCETYPE,
        "index": SPLUNK_INDEX,
        "event": {
            "_time": e.ts.isoformat() if e.ts else None,
            "host": e.host, "user": e.user, "src": e.src_ip,
            "action": e.action, "message": e.details
        }
    }

def _as_splunk_finding(f: Finding):
    return {
        "time": int(f.ts.timestamp()) if f.ts else int(datetime.utcnow().timestamp()),
        "host": f.host,
        "source": "threatscope",
        "sourcetype": "threatscope:finding",
        "index": SPLUNK_INDEX,
        "event": {
            "_time": f.ts.isoformat() if f.ts else None,
            "host": f.host, "user": f.user, "src": None,
            "action": f.rule, "severity": f.severity, "message": f.context
        }
    }

@app.post("/export_to_splunk")
def export_to_splunk(limit: int = 200, db: Session = Depends(get_db)):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        # Graceful message if not configured
        raise HTTPException(status_code=400, detail="SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN not configured")
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}", "Content-Type": "application/json"}

    events = db.query(Event).order_by(Event.ts.desc()).limit(limit).all()
    findings = db.query(Finding).order_by(Finding.ts.desc()).limit(limit).all()
    batch = [_as_splunk_event(e) for e in events] + [_as_splunk_finding(f) for f in findings]

    ok = 0
    failed = 0
    for item in batch:
        try:
            r = requests.post(SPLUNK_HEC_URL, headers=headers, json=item, timeout=10)
            if r.status_code == 200 and r.json().get("code") == 0:
                ok += 1
            else:
                failed += 1
        except Exception:
            failed += 1
    return {"sent": ok, "failed": failed}
