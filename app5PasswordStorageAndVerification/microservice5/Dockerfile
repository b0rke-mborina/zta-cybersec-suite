FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_OA_MICROSERVICE_ENCRYPTION=http://zta-microservice6/zta/encrypt

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8044

CMD ["uvicorn", "microservice5Logging:app", "--host", "0.0.0.0", "--port", "8044"]