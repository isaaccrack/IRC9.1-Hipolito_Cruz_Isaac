FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ansible openssh-client sudo && \
    apt-get clean

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
COPY ansible/ ../ansible/
RUN chmod 600 ../ansible/keys/id_rsa

CMD ["python", "app.py"]

