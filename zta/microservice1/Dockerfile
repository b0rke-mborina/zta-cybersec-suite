FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_MONITORING_MICROSERVICE=http://zta-microservice7/zta/monitoring
ENV URL_ACL_MICROSERVICE=http://zta-microservice4/zta/acl

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["uvicorn", "microservice1PolicyAndGovernance:app", "--host", "0.0.0.0", "--port", "8080"]