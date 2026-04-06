# Mobile Line & Device Management

Desktop application built with **Python and Tkinter** for corporate mobile line management — tracking SIM cards, PIN/PUK data, device assignments, employee ownership and operational audit history. Backed by SQL Server with role-based access control.

---

## Overview

| Layer | Technology | Role |
|---|---|---|
| UI | Python + Tkinter | Desktop interface |
| Data access | pyodbc + pandas | SQL Server integration |
| Persistence | SQL Server | Operational data store |
| Export | openpyxl | Excel reporting |

---

## Features

### Role-based access control
Two access levels with differentiated permissions:
- **Admin** — full access: create, edit and delete lines, devices and assignments; manage users; trigger synchronization
- **User** — restricted access: read-only on sensitive areas, operational access on assigned modules

### Mobile line management
Full lifecycle tracking of corporate SIM cards: line number, operator, status, PIN/PUK data and assignment history.

### Device & employee assignment
Workflows to assign and reassign devices and mobile lines to employees, with validation to prevent conflicts and orphaned records.

### CSV synchronization
Safe import pipeline with upsert logic — new records are inserted, existing ones updated, no data is silently overwritten without validation. Handles heterogeneous source formats with normalization and deduplication.

### Audit trail
Every operational change is logged with timestamp and responsible user, providing a full history of assignments, modifications and synchronization events.

### Excel export
Reporting exports via openpyxl for support workflows, inventory reviews and management reporting.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           Tkinter Desktop UI             │
│                                         │
│  ┌─────────────┐   ┌─────────────────┐  │
│  │  Admin view  │   │   User view     │  │
│  │  (full CRUD) │   │  (read + ops)   │  │
│  └──────┬──────┘   └────────┬────────┘  │
│         └──────────┬────────┘           │
│              Auth layer                 │
└──────────────────┬──────────────────────┘
                   │
              SQL Server
         (lines, devices, users,
          assignments, audit log)
```

---

## Tech Stack

`Python` `Tkinter` `SQL Server` `pandas` `pyodbc` `openpyxl`

---

## Project Structure

```
gestor_moviles.py     # Application entry point
requirements.txt      # Python dependencies
app/
  auth/               # Login and role validation
  views/              # Admin and user interface modules
  services/           # Business logic (sync, assignment, audit)
  db/                 # SQL Server connection and query helpers
  export/             # Excel export logic
```

---

## Setup

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
source venv/bin/activate    # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
GM_SQL_SERVER=your_server
GM_SQL_DB=your_database
GM_SQL_USER=your_user
GM_SQL_PASSWORD=your_password

# 4. Run
python gestor_moviles.py
```

---

## Notes

This repository is a sanitized portfolio version. It does not include company data, credentials, production exports or internal deployment artifacts. The project structure shown above reflects the original organization and may differ slightly from the exported version.

---

## Stack

`Python` `Tkinter` `SQL Server` `pyodbc` `pandas` `openpyxl` `Desktop App` `Role-based Access Control`
