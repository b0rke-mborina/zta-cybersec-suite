FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8053

CMD ["uvicorn", "microservice4AccessControl:app", "--host", "0.0.0.0", "--port", "8053"]