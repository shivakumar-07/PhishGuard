FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishguard/ phishguard/
COPY models/ models/
COPY results/*.json results/

EXPOSE 8000
CMD ["uvicorn", "phishguard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
