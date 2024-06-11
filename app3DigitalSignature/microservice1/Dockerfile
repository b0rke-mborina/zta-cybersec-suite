FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_ACCESSCONTROL_MICROSERVICE=http://127.0.0.1:8021/digital-signature/access-control
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8022/digital-signature/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8020

CMD ["uvicorn", "microservice1Verification:app", "--host", "0.0.0.0", "--port", "8020"]