ThreatScope quick start

Step 1
Install Python 3 if you do not have it

Step 2
Create a virtual environment and install packages

Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

macOS or Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Step 3
Run the app

uvicorn app.main:app --reload

Step 4
Open http://127.0.0.1:8000 in your browser
Click Load demo data
Use the Hunt view and the CSV ingest panel
