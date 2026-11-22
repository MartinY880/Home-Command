FROM python:3.13-slim
RUN pip install --no-cache-dir maxminddb && useradd -r -u 10001 -d /data homecommand && mkdir -p /app /data && chown homecommand /data
WORKDIR /app
COPY portal.py portal-shipper.py ./
COPY static ./static
ENV HC_DATA=/data HC_PORT=3000 HC_STATE=/data/shipper-state.json PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 3000/tcp 5514/udp 2055/udp
USER homecommand
CMD ["python3", "/app/portal.py"]
