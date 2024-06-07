FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_MONITORING_MICROSERVICE=http://127.0.0.1:8087/zta/monitoring
ENV URL_ACL_MICROSERVICE=http://127.0.0.1:8083/zta/acl

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["uvicorn", "microservice1PolicyAndGovernance:app", "--host", "0.0.0.0", "--port", "8080"]