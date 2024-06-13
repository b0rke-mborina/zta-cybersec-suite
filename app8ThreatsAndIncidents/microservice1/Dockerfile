FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_INCIDENT=http://app8-microservice3/intelligence/incident
ENV URL_LOGGING_MICROSERVICE=http://app8-microservice5/intelligence/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8070

CMD ["uvicorn", "microservice1IncidentReporting:app", "--host", "0.0.0.0", "--port", "8070"]