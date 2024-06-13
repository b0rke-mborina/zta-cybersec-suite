FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_THREATS=http://127.0.0.1:8072/intelligence/threats
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8074/intelligence/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8071

CMD ["uvicorn", "microservice2ThreatSharing:app", "--host", "0.0.0.0", "--port", "8071"]