FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8061

CMD ["uvicorn", "microservice2Storage:app", "--host", "0.0.0.0", "--port", "8061"]