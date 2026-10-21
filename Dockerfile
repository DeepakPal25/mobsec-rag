FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/mobsec
COPY pyproject.toml README.md LICENSE ./
COPY mobsec ./mobsec
RUN pip install --no-cache-dir . \
 && MOBSEC_HOME=/opt/mobsec/kb mobsec ingest \
 && rm -rf /opt/mobsec/kb/src/*/.git

ENV MOBSEC_HOME=/opt/mobsec/kb
RUN useradd -m scanner
USER scanner
WORKDIR /work
ENTRYPOINT ["mobsec"]
CMD ["--help"]
# docker build -t mobsec-rag .
# docker run --rm -v "$PWD:/work" mobsec-rag scan app.apk -o report
# docker run --rm -p 8765:8765 mobsec-rag serve --host 0.0.0.0 --no-browser
