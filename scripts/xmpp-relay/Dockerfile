# wadamesh XMPP relay. relay.ini and the database live in the /data volume;
# nothing secret is copied into the image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY xmpp_relay.py .

RUN useradd --system --uid 10001 relay && mkdir /data && chown relay /data
USER relay
VOLUME /data
EXPOSE 8765

CMD ["python3", "xmpp_relay.py", "/data/relay.ini"]
