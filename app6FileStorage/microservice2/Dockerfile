FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_CRYPTOGRAPHY_MICROSERVICE_ENCRYPT=http://127.0.0.1:8052/file/encrypt
ENV URL_CRYPTOGRAPHY_MICROSERVICE_DECRYPT=http://127.0.0.1:8052/file/decrypt
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://127.0.0.1:8086/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8051

CMD ["uvicorn", "microservice5Logging:app", "--host", "0.0.0.0", "--port", "8051"]