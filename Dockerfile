FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Seed database on build
RUN python -m dtem.data.seed_data

EXPOSE 8000

CMD ["uvicorn", "dtem.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
