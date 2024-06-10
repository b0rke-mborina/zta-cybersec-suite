FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_IAM_MICROSERVICE=http://zta-microservice2/zta/iam
ENV URL_NETWORK_MICROSERVICE=http://zta-microservice3/zta/network
ENV URL_ACL_MICROSERVICE=http://zta-microservice4/zta/acl
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt
ENV URL_MONITORING_MICROSERVICE=http://zta-microservice7/zta/monitoring

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8085

CMD ["uvicorn", "microservice5SecureTunnelling:app", "--host", "0.0.0.0", "--port", "8085"]