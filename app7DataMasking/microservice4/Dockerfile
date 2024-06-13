FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://127.0.0.1:8086/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8063

CMD ["uvicorn", "microservice4Logging:app", "--host", "0.0.0.0", "--port", "8063"]