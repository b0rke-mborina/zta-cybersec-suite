from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, validator
import asyncio
import datetime
import json
from enum import Enum
from .utilityFunctions import log, reportToAdmin


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

	@validator("timestamp")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	reportToAdmin("Fatal error.")

	return JSONResponse(
		status_code = 500,
		content = { "monitoring": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/zta/monitoring")
async def identityAndAccessManagement(data: Data):
	tasks = [log(data, "ztaLogs.db"), reportToAdmin("Fatal error.")]
	await asyncio.gather(*tasks)
	return { "monitoring": "success" }
