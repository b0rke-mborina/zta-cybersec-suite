FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_STORAGE=http://app6-microservice3/file/storage
ENV URL_STORAGE_MICROSERVICE_RETRIEVAL=http://app6-microservice3/file/retrieval
ENV URL_ACCESSCONTROL_MICROSERVICE=http://app6-microservice4/file/access-control
ENV URL_LOGGING_MICROSERVICE=http://app6-microservice5/file/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8050

CMD ["uvicorn", "microservice1Sharing:app", "--host", "0.0.0.0", "--port", "8050"]