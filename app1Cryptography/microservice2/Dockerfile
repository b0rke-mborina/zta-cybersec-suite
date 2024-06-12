FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_LOGGING_MICROSERVICE=http://app1-microservice3/cryptography/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8002

CMD ["uvicorn", "microservice2Decryption:app", "--host", "0.0.0.0", "--port", "8002"]