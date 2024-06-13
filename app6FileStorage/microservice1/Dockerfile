FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_STORAGE=http://127.0.0.1:8051/file/storage
ENV URL_STORAGE_MICROSERVICE_RETRIEVAL=http://127.0.0.1:8051/file/retrieval
ENV URL_ACCESSCONTROL_MICROSERVICE=http://127.0.0.1:8053/file/access-control
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8054/file/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8050

CMD ["uvicorn", "microservice1Sharing:app", "--host", "0.0.0.0", "--port", "8050"]