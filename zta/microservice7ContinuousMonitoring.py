from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from enum import Enum
from .utilityFunctions import isStringValid, log, reportToAdmin, sendRequest


app = FastAPI()


class Level(str, Enum):
	INFO = "INFO"
	DEBUG = "DEBUG"
	WARN = "WARN"
	ERROR = "ERROR"
	FATAL = "FATAL"

class Data(BaseModel):
	timestamp: str
	level: Level
	logger_source: int
	user_id: int
	request: str
	response: str
	error_message: str
	
	class Config:
		use_enum_values = True

	@validator("timestamp")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

	@validator("request", "response", "error_message")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	dataForGovernanceUnsuccessfulRequest = {
		"problem": "total_system_failure"
	}
	await sendRequest("post", "http://127.0.0.1:8080/zta/governance", dataForGovernanceUnsuccessfulRequest)

	return JSONResponse(
		status_code = 500,
		content = { "monitoring": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/zta/monitoring")
async def monitoring(data: Data):
	dataForEncryption = data.model_dump()
	dataForEncryption["timestamp"] = dataForEncryption["timestamp"].translate(str.maketrans("\"'{}:", "_____"))

	orchestrationAutomationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8086/zta/encrypt",
		{
			"data": dataForEncryption
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	logData = orchestrationAutomationResult[0].get("data")

	await log(logData, "ztaLogs.db")

	return { "monitoring": "success" }
