FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_POLICY_MICROSERVICE=http://127.0.0.1:8043/password/policy
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8044/password/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://127.0.0.1:8086/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8040

CMD ["uvicorn", "microservice1StorageAndRetrieval:app", "--host", "0.0.0.0", "--port", "8040"]