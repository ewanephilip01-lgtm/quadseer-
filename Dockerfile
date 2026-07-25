FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Install Python packages one by one to catch failures
RUN pip install --no-cache-dir fastapi==0.109.2 uvicorn==0.27.0 pydantic==2.6.1
RUN pip install --no-cache-dir email-validator==2.1.0
RUN pip install --no-cache-dir sqlalchemy==2.0.25 asyncpg==0.29.0
RUN pip install --no-cache-dir bcrypt==4.1.2 PyJWT==2.8.0
RUN pip install --no-cache-dir httpx==0.26.0
RUN pip install --no-cache-dir celery==5.3.6 redis==5.0.1
RUN pip install --no-cache-dir dnspython==2.5.0
RUN pip install --no-cache-dir jinja2==3.1.3 python-multipart==0.0.6
RUN pip install --no-cache-dir aiofiles==23.2.1

# Verify critical imports
RUN python -c "import jwt; print('PyJWT OK:', jwt.__version__)"
RUN python -c "import bcrypt; print('bcrypt OK')"
RUN python -c "import fastapi; print('FastAPI OK:', fastapi.__version__)"
RUN python -c "import sqlalchemy; print('SQLAlchemy OK:', sqlalchemy.__version__)"
RUN python -c "from pydantic import EmailStr; print('EmailStr OK')"

# Copy application
COPY app/ ./app/
COPY scripts/ ./scripts/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
