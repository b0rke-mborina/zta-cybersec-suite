FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_NEW=http://127.0.0.1:8012/auth-generator/data-new
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8013/auth-generator/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://127.0.0.1:8086/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8010

CMD ["uvicorn", "microservice1Generation:app", "--host", "0.0.0.0", "--port", "8010"]