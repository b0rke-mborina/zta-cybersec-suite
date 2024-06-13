FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8073

CMD ["uvicorn", "microservice4Analysis:app", "--host", "0.0.0.0", "--port", "8073"]