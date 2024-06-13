from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import datetime
import os
from enum import Enum
from utilityFunctions import isStringValid, log, sendRequest


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
	user_id: str
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

	@field_validator("user_id", "request", "response", "error_message")
	def validateAndSanitizeString(cls, v, info):
		regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' if info.field_name == "user_id" else r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$'
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
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
		content = { "logging": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/data/logging", status_code = 200)
async def logging(data: Data):
	dataForEncryption = data.model_dump()
	dataForEncryption["timestamp"] = dataForEncryption["timestamp"].translate(str.maketrans("\"'{}:", "_____"))

	userId = dataForEncryption["user_id"]
	del dataForEncryption["user_id"]

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": dataForEncryption
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	
	logData = orchestrationAutomationResult[0].get("data")
	logData["user_id"] = userId
	await log(logData, "app7Logs.db")

	return { "logging": "success" }
