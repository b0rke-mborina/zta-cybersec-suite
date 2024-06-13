FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_CRYPTOGRAPHY_MICROSERVICE_ENCRYPT=http://app6-microservice3/file/encrypt
ENV URL_CRYPTOGRAPHY_MICROSERVICE_DECRYPT=http://app6-microservice3/file/decrypt
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8051

CMD ["uvicorn", "microservice2Storage:app", "--host", "0.0.0.0", "--port", "8051"]