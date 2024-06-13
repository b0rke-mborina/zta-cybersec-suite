FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_INFO=http://app2-microservice3/auth-generator/data-info
ENV URL_LOGGING_MICROSERVICE=http://app2-microservice4/auth-generator/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8011

CMD ["uvicorn", "microservice2Verification:app", "--host", "0.0.0.0", "--port", "8011"]