FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_STORAGE_MICROSERVICE_RETRIEVE=http://app5-microservice1/password/retrieve
ENV URL_LOGGING_MICROSERVICE=http://app5-microservice5/password/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8041

CMD ["uvicorn", "microservice2Verification:app", "--host", "0.0.0.0", "--port", "8041"]