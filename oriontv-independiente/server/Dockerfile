FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10101 -m orion && mkdir /data && chown orion:orion /data
COPY . .
USER orion
ENV ORION_DATA=/data
EXPOSE 8099
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8099","--no-access-log"]
