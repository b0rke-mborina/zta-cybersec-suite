FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_RETRIEVE=http://127.0.0.1:8040/password/retrieve
ENV URL_STORAGE_MICROSERVICE_UPDATE=http://127.0.0.1:8040/password/update
ENV URL_POLICY_MICROSERVICE=http://127.0.0.1:8043/password/policy
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8044/password/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8042

CMD ["uvicorn", "microservice3ResetAndRecovery:app", "--host", "0.0.0.0", "--port", "8042"]