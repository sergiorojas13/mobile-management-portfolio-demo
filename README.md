# Mobile Line and Device Management

Desktop application built with Python, Tkinter and SQL Server to manage corporate mobile lines, SIM and PIN/PUK information, device assignments and audit history.

## Highlights
- Role-based authentication
- Mobile line management
- Device and employee assignment workflows
- Safe CSV synchronization with upsert logic
- Audit trail for operational changes
- Excel export for reporting and support
- Data normalization and validation for heterogeneous sources

## Tech Stack
- Python
- Tkinter
- SQL Server
- pandas
- pyodbc
- openpyxl

## Notes
This repository is a sanitized portfolio version. It does not include company data, credentials, production exports or internal deployment artifacts.

## Run
1. Create a virtual environment
2. Install dependencies from requirements.txt
3. Configure environment variables:
   - GM_SQL_SERVER
   - GM_SQL_DB
   - GM_SQL_USER
   - GM_SQL_PASSWORD
4. Run:
   python gestor_moviles.py
