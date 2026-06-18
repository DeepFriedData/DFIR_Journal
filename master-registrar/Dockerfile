FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Ensure database directory exists
RUN mkdir -p database

EXPOSE 5000

CMD ["python", "server.py"]
