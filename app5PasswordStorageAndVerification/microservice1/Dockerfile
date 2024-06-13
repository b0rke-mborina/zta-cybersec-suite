FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_POLICY_MICROSERVICE=http://app5-microservice4/password/policy
ENV URL_LOGGING_MICROSERVICE=http://app5-microservice5/password/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8040

CMD ["uvicorn", "microservice1StorageAndRetrieval:app", "--host", "0.0.0.0", "--port", "8040"]