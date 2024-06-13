FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_ANALYSIS_MICROSERVICE=http://127.0.0.1:8073/intelligence/analysis
ENV URL_GOVERNANCE_MICROSERVICE=http://127.0.0.1:8080/zta/governance

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8072

CMD ["uvicorn", "microservice3DataSharing:app", "--host", "0.0.0.0", "--port", "8072"]