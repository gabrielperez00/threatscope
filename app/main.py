from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from typing import List, Dict, Any
import requests

from . import models
from .database import SessionLocal, engine
from .models import Event, Finding

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    total_findings = db.query(Finding).count()
    findings = db.query(Finding).order_by(Finding.ts.desc()).limit(5).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_events": total_events,
        "total_findings": total_findings,
        "findings": findings
    })

@app.get("/hunt", response_class=HTMLResponse)
def hunt(request: Request, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.ts.desc()).all()
    return templates.TemplateResponse("hunt.html", {
        "request": request,
        "events": events
    })

@app.get("/map", response_class=HTMLResponse)
def map_view(request: Request, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.ts.desc()).all()
    return templates.TemplateResponse("map.html", {
        "request": request,
        "events": events
    })

@app.get("/hunt_table")
def hunt_table(request: Request, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.ts.desc()).all()
    return templates.TemplateResponse("hunt_table.html", {
        "request": request,
        "events": events
    })
@app.get("/events_geo")
def events_geo(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    rows = (
        db.query(Event)
        .filter(Event.geo_lat.isnot(None), Event.geo_lon.isnot(None))
        .order_by(Event.ts.desc())
        .limit(2000)
        .all()
    )
    return [
        {
            "ts": e.ts.isoformat(),
            "user": e.user,
            "host": e.host,
            "action": e.action,
            "details": e.details or "",
            "lat": e.geo_lat,
            "lon": e.geo_lon,
        }
        for e in rows
    ]

# =====================
# Detection Rules Logic
# =====================

def run_rules(db: Session):
    events = db.query(Event).order_by(Event.ts).all()
    if not events:
        return

    # 1) Off hour login (TA0006/Valid Accounts)
    for e in events:
        if e.action == "login_success":
            if e.ts.hour < 6 or e.ts.hour > 22:
                db.add(Finding(
                    ts=e.ts,
                    user=e.user,
                    host=e.host,
                    rule="Off hour login (TA0006/Valid Accounts)",
                    severity="Low",
                    context="user logged in outside 06:00–22:00"
                ))

    # 2) Brute force success (TA0006/T1110)
    failures = {}
    for e in events:
        if e.action == "login_failure":
            failures.setdefault((e.user, e.src_ip), []).append(e)
        if e.action == "login_success":
            if (e.user, e.src_ip) in failures and len(failures[(e.user, e.src_ip)]) >= 5:
                db.add(Finding(
                    ts=e.ts,
                    user=e.user,
                    host=e.host,
                    rule="Brute force success (TA0006/T1110)",
                    severity="High",
                    context=f"{len(failures[(e.user, e.src_ip)])} prior failures from {e.src_ip}"
                ))

    # 3) Suspicious PowerShell encoded (TA0002/T1059.001)
    for e in events:
        if "powershell" in (e.details or "").lower() and "-enc" in (e.details or "").lower():
            db.add(Finding(
                ts=e.ts,
                user=e.user,
                host=e.host,
                rule="Suspicious PowerShell encoded (TA0002/T1059.001)",
                severity="High",
                context=e.details
            ))

    # 4) Impossible travel (TA0006/Account Use Anomaly)
    last_login = {}
    loc_cache = {}
    for e in events:
        if e.action == "login_success" and e.src_ip:
            last = last_login.get(e.user)
            if e.src_ip not in loc_cache:
                try:
                    resp = requests.get(f"https://ipapi.co/{e.src_ip}/json/").json()
                    loc_cache[e.src_ip] = resp.get("country_name")
                except:
                    loc_cache[e.src_ip] = None
            loc = loc_cache[e.src_ip]
            if last:
                last_loc, last_time = last
                if loc and last_loc and loc != last_loc and (e.ts - last_time).total_seconds() < 3600:
                    db.add(Finding(
                        ts=e.ts,
                        user=e.user,
                        host=e.host,
                        rule="Impossible travel (TA0006/Account Use Anomaly)",
                        severity="Medium",
                        context=f"{e.src_ip}={loc}, previous={last_loc} {last_time}"
                    ))
            last_login[e.user] = (loc, e.ts)

    # 5) Lateral movement (TA0008)
    user_hosts = {}
    for e in events:
        if e.action == "login_success":
            prev = user_hosts.setdefault(e.user, set())
            if e.host not in prev and len(prev) >= 2:
                db.add(Finding(
                    ts=e.ts,
                    user=e.user,
                    host=e.host,
                    rule="Lateral movement (TA0008)",
                    severity="Medium",
                    context=f"user previously logged into {', '.join(list(prev)[:3])}"
                ))
            prev.add(e.host)

    # 6) New host for user (TA0008)
    seen_hosts = {}
    for e in events:
        if e.action == "login_success":
            prev = seen_hosts.setdefault(e.user, set())
            if e.host not in prev:
                sev = "Low" if len(prev) == 0 else "Medium"
                note = "first observed host for user" if len(prev) == 0 else f"new host (previous: {', '.join(list(prev)[:3])})"
                db.add(Finding(
                    ts=e.ts,
                    user=e.user,
                    host=e.host,
                    rule="New host for user (TA0008)",
                    severity=sev,
                    context=note
                ))
                prev.add(e.host)

    db.commit()
