import json
from fastapi import FastAPI
from pydantic import BaseModel, model_validator, validator
import uvicorn
import datetime
from enum import Enum


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

def make_external_request():
	print("HERE")
	raise ExternalServiceUnavailableError()

class ExternalServiceUnavailableError(Exception):
	pass

@app.get("/cryptography/logging", status_code = 200)
async def logging(data: Data):
	print("I AM AT LOGGING MICROSERVICE")
	print(data)
	return {"result": "logging success"}
	try:
		return { "logging": "success" }
	except Exception as e:
		return { "logging": "failure", "error_message": str(e) }

# uvicorn app1Cryptography.microservice4Logging:app --reload --host 127.0.0.1 --port 8004