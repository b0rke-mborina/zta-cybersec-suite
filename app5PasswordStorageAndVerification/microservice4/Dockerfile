FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_MONITORING_MICROSERVICE=http://zta-microservice7/zta/monitoring

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8043

CMD ["uvicorn", "microservice4PolicyEnforcement:app", "--host", "0.0.0.0", "--port", "8043"]