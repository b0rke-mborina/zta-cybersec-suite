FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_STORE=http://127.0.0.1:8061/data/store
ENV URL_STORAGE_MICROSERVICE_RETRIEVE=http://127.0.0.1:8061/data/retrieve
ENV URL_ACCESSCONTROL_MICROSERVICE=http://127.0.0.1:8062/data/access-control
ENV URL_LOGGING_MICROSERVICE=http://127.0.0.1:8063/data/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://127.0.0.1:8085/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://127.0.0.1:8086/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8060

CMD ["uvicorn", "microservice1DataMasking:app", "--host", "0.0.0.0", "--port", "8060"]