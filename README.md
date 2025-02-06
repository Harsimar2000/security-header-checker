# Security Header Checker 🔒

A Python CLI tool to audit website security headers, calculate compliance scores, and store results in PostgreSQL.
Built to quickly identify missing security headers that could expose web applications to attacks.

## Key Features

- Checks for 7 critical security headers
- Calculates a compliance score (0-100%)
- Stores results in PostgreSQL for historical tracking
- Simple CLI interface with clear reporting

## Prerequisites

- Python 3.8+
- PostgreSQL 15+
- `pip` package manager

## Installation

1. **Clone the repository**

```bash
git clone https://github.com/Harsimar2000/security-header-checker.git
cd security-header-checker
```

2. **Install Dependencies**

```bash
pip install -r requirements.txt
```

2. **Configure Environments**

```bash
cp .env.example .env
```

Edit .env with your PostgreSQL credentials:

```bash
DB_NAME=security_headers
DB_USER=your_username
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
```

## Usage

Check a single website

```bash
python3 security_headers_checker.py https://example.com
```
