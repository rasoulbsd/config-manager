# API Manager Panel

Web portal for distributing per-client configuration to authenticated users, with an administrator panel for managing accounts.

## Features

- Admin and client roles with server-side password hashing (Werkzeug `scrypt`)
- JSON persistence (path configurable via `DATA_DIR`)
- Clean URL routing (`/`, `/dashboard`)
- Health endpoint: `GET /api/health`
- Docker image with Gunicorn and a non-root user

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
copy .env.example .env
# edit .env values as needed
python app.py --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/`.

`app.py` auto-loads `.env` from the project root for direct Python runs. Runtime precedence is:

1. CLI args (`--host`, `--port`, `--debug`)
2. Environment variables (`HOST`, `PORT`, `FLASK_DEBUG`)
3. App defaults (`0.0.0.0`, `8080`, debug off)

On first run, if `database.json` does not exist and `ADMIN_PASSWORD` is not set, the server generates a random initial password and prints `INITIAL_ADMIN_PASSWORD=...` to stderr.

Important: `ADMIN_USERNAME` and `ADMIN_PASSWORD` seed credentials when the database is first created. If `database.json` already exists, those values are not reapplied unless you enable `SYNC_ADMIN_FROM_ENV=1`.

## Run with Docker Compose

1. Copy `.env.example` to `.env` and set `ADMIN_PASSWORD` to a strong secret before the first start (or read the generated password from logs once).
2. Start:

```bash
docker compose up -d --build
```

3. Open `http://localhost:8080/` (or the port you set in `.env`).

Data is stored in the `config_data` Docker volume at `/data/database.json` inside the container.

## Production notes

- Terminate TLS at a reverse proxy (for example Traefik, Caddy, or nginx) and do not expose the app directly on the public internet without HTTPS.
- Set `ADMIN_PASSWORD` before the database is created, or capture the one-time password from logs.
- Back up the volume or `database.json` regularly.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Liveness (JSON `{"status":"ok"}`) |
| POST | `/api/login` | JSON body: `username`, `password` |
| POST | `/api/save` | Admin only: `auth_user`, `auth_pass`, `db` (full database object) |

Direct `GET` requests under `/api/*` other than `/api/health` return 403 by design.
