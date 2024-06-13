FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_NEW=http://app2-microservice3/auth-generator/data-new
ENV URL_LOGGING_MICROSERVICE=http://app2-microservice4/auth-generator/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8010

CMD ["uvicorn", "microservice1Generation:app", "--host", "0.0.0.0", "--port", "8010"]