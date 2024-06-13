FROM python:3.10

WORKDIR /app

COPY . /app

ENV URL_ANALYSIS_MICROSERVICE=http://app8-microservice4/intelligence/analysis
ENV URL_GOVERNANCE_MICROSERVICE=http://zta-microservice1/zta/governance

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8072

CMD ["uvicorn", "microservice3DataSharing:app", "--host", "0.0.0.0", "--port", "8072"]