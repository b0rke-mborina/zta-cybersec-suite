from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import log, sendRequest


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
	response: str = ""
	error_message: str = ""

	class Config:
		use_enum_values = True

	@validator("timestamp")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "logging": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/cryptography/logging", status_code = 200)
async def logging(data: Data):
	orchestrationAutomationResult = await sendRequest(
		"get",
		"http://127.0.0.1:8086/zta/encrypt",
		{
			"data": data.model_dump()
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	
	logData = orchestrationAutomationResult[0].get("data")
	await log(logData, "app1Logs.db")

	return { "logging": "success" }