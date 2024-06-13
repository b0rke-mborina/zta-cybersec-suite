FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_STORE=http://app7-microservice2/data/store
ENV URL_STORAGE_MICROSERVICE_RETRIEVE=http://app7-microservice2/data/retrieve
ENV URL_ACCESSCONTROL_MICROSERVICE=http://app7-microservice3/data/access-control
ENV URL_LOGGING_MICROSERVICE=http://app7-microservice4/data/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8060

CMD ["uvicorn", "microservice1DataMasking:app", "--host", "0.0.0.0", "--port", "8060"]