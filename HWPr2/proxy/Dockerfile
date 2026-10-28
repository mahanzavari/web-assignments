FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

# Use a fast PyPI mirror with generous timeout and retries
RUN pip install --no-cache-dir \
    -i https://mirror-pypi.runflare.com/simple \
    -r requirements.txt

COPY main.py .

EXPOSE 80

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
