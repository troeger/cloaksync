FROM python:alpine

COPY deployment/requirements-prod.txt /tmp/

RUN apk add build-base libffi-dev && \
    pip install --no-cache-dir -r /tmp/requirements-prod.txt && \
    apk del build-base && \
    mkdir /code/

COPY sync.py /code/
COPY .env.default /code/.env

CMD ["python", "/code/sync.py"]
