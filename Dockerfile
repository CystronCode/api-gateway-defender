# ─── Build stage ─────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install dependencies into a prefix we'll copy to the final image
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ─── Runtime stage ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Hugging Face Spaces expects the app on port 7860
ENV PORT=7860
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy pre-installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY env.py      .
COPY main.py     .
COPY baseline.py .

# HF Spaces: non-root user for safety
RUN useradd -m -u 1000 appuser && chown -R appuser /app
USER appuser

EXPOSE 7860

# Increase workers for concurrent evaluation runs
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860", "--workers", "1"]
