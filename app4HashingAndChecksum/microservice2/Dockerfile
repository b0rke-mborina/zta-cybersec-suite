FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_REPORTING_MICROSERVICE=http://app4-microservice3/hashing/reporting
ENV URL_LOGGING_MICROSERVICE=http://app4-microservice5/hashing/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8031

CMD ["uvicorn", "microservice2ChecksumVerification:app", "--host", "0.0.0.0", "--port", "8031"]