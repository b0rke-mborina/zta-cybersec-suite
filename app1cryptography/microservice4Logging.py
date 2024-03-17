from fastapi import FastAPI
from pydantic import BaseModel, validator
from enum import Enum
import datetime

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

@app.get("/cryptography/logging", status_code = 200)
def logging(data: Data):
	print(data)
	try:
		return { "logging": "success" }
	except Exception as e:
		return { "logging": "failure", "error_message": str(e) }
