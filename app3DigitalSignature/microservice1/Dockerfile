FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_ACCESSCONTROL_MICROSERVICE=http://app3-microservice2/digital-signature/access-control
ENV URL_LOGGING_MICROSERVICE=http://app3-microservice3/digital-signature/logging
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance
ENV URL_TUNNELLING_MICROSERVICE=http://zta-microservice5/zta/tunnelling

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8020

CMD ["uvicorn", "microservice1Verification:app", "--host", "0.0.0.0", "--port", "8020"]