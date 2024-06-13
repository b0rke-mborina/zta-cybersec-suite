FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_THREATS=http://app8-microservice3/intelligence/threats
ENV URL_LOGGING_MICROSERVICE=http://app8-microservice5/intelligence/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8071

CMD ["uvicorn", "microservice2ThreatSharing:app", "--host", "0.0.0.0", "--port", "8071"]