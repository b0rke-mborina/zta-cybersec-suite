FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8003/cryptography/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8001

CMD ["uvicorn", "microservice1Encryption:app", "--host", "0.0.0.0", "--port", "8001"]