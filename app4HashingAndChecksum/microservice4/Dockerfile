FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_MONITORING_MICROSERVICE=http://127.0.0.1:8087/zta/monitoring

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8033

CMD ["uvicorn", "microservice4PasswordPolicyManagement:app", "--host", "0.0.0.0", "--port", "8033"]