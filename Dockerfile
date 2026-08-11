FROM python:3.12.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt \
    && groupadd --system alert2ir \
    && useradd --system --gid alert2ir --no-create-home alert2ir

COPY src/alert2ir ./alert2ir
COPY alembic.ini .
COPY migrations ./migrations

USER alert2ir

EXPOSE 8000

CMD ["uvicorn", "alert2ir.main:app", "--host", "0.0.0.0", "--port", "8000"]
