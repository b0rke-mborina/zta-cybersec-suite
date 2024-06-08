FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_IAM_MICROSERVICE=http://127.0.0.1:8081/zta/iam
ENV URL_NETWORK_MICROSERVICE=http://127.0.0.1:8082/zta/network
ENV URL_ACL_MICROSERVICE=http://127.0.0.1:8083/zta/acl
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://127.0.0.1:8086/zta/encrypt
ENV URL_MONITORING_MICROSERVICE=http://127.0.0.1:8087/zta/monitoring

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8085

CMD ["uvicorn", "microservice5SecureTunnelling:app", "--host", "0.0.0.0", "--port", "8085"]