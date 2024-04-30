from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
from enum import Enum
from .utilityFunctions import sendRequest


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class Incident(BaseModel):
	timestamp: str
	affected_assets: list
	attack_vectors: list
	malicious_code: list
	compromised_data: list
	indicators_of_compromise: list
	severity: Severity
	user_accounts_involved: list
	logs: list
	actions: list

	@validator("timestamp")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

class DataReport(BaseModel):
	incident: Incident

class DataRetrieve(BaseModel):
	time_from: str
	time_to: str
	severity: Severity

	@validator("time_from")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Value of time_from must be in ISO 8601 format")
		return v

	@validator("time_to")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Value of time_to must be in ISO 8601 format")
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 1,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8074/intelligence/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "intelligence": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "intelligence": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/intelligence/report", status_code = 200)
async def reporting(data: DataReport):
	return { "reporting": "success" }

@app.get("/intelligence/retrieve", status_code = 200)
async def retrieval(data: DataRetrieve):
	return { "retrieval": "success" }
