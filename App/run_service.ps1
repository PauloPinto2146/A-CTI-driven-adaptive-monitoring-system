# Terminal 1 — serviço principal
cd application-for-sysmon
uv run python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2 — mock do ip-api
cd mock-ip-api
uv run python -m uvicorn app.main:app --host 0.0.0.0 --port 9000