from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
import os
from enum import Enum
from .utilityFunctions import getAuthData, sendRequest, validateThreatRequest


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class Data(BaseModel):
	time_from: str
	time_to: str
	severity: Severity
	
	class Config:
		use_enum_values = True

	@validator("time_from", "time_to")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Time value must be in ISO 8601 format.")
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 82,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", os.getenv("URL_LOGGING_MICROSERVICE"), dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "retrieval": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		os.getenv("URL_GOVERNANCE_MICROSERVICE"),
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "retrieval": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/intelligence/retrieve", status_code = 200)
async def retrieval(request: Request, data: Data):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 82
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	validateThreatRequest(data.time_from, data.time_to)

	dataSharingResult = await sendRequest(
		"get",
		os.getenv("URL_STORAGE_MICROSERVICE_THREATS"),
		{
			"time_from": data.time_from,
			"time_to": data.time_to,
			"severity": data.severity,
		}
	)
	if dataSharingResult[0].get("threats") != "success":
		raise HTTPException(500)
	
	threatsData = dataSharingResult[0].get("data")
	response = { "retrieval": "success", "data": threatsData }

	loggingResult = await sendRequest(
		"post",
		os.getenv("URL_LOGGING_MICROSERVICE"),
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 82,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}[]:", "_______")),
			"response": str(response).translate(str.maketrans("\"'{}[]:", "_______")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
