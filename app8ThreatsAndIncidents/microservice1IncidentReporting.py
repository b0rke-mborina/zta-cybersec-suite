import asyncio
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
from enum import Enum
from .utilityFunctions import getAuthData, isStringValid, sendRequest, validateIncidentData


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

	@validator("affected_assets", "malicious_code", "compromised_data", "indicators_of_compromise", "user_accounts_involved", "logs", "actions")
	def validateAndSanitizeList(cls, v):
		for item in v:
			if isinstance(item, str):
				isValid = isStringValid(item, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$')
				if not isValid:
					raise RequestValidationError("String is not valid.")
			else:
				raise RequestValidationError("Request not valid.")
		
		return v

	@validator("attack_vectors")
	def validateAndSanitizeList(cls, v):
		if not all(isinstance(item, list) for item in v):
			raise RequestValidationError("Request not valid.")
		
		for item in v:
			for value in item:
				if isinstance(value, str):
					isValid = isStringValid(value, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$')
					if not isValid:
						raise RequestValidationError("String is not valid.")
				else:
					raise RequestValidationError("Request not valid.")
		
		return v

class Data(BaseModel):
	incident: Incident
	
	class Config:
		use_enum_values = True

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 81,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", "http://127.0.0.1:8074/intelligence/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "reporting": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "reporting": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/intelligence/report", status_code = 200)
async def reporting(request: Request, data: Data):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 81
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	validateIncidentData(data.incident)
	response = { "reporting": "success" }

	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8072/intelligence/incident",
			{
				"user_id": userId,
				"username": request.headers.get("username"),
				"timestamp": data.incident.timestamp,
				"affected_assets": data.incident.affected_assets,
				"attack_vectors": data.incident.attack_vectors,
				"malicious_code": data.incident.malicious_code,
				"compromised_data": data.incident.compromised_data,
				"indicators_of_compromise": data.incident.indicators_of_compromise,
				"severity": data.incident.severity,
				"user_accounts_involved": data.incident.user_accounts_involved,
				"logs": data.incident.logs,
				"actions": data.incident.actions
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8074/intelligence/logging",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 81,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}[]:", "_______")),
				"response": str(response).translate(str.maketrans("\"'{}[]:", "_______")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("incident") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)

	return response
