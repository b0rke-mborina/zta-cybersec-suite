from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import incidentIncludesThisSystem


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class Data(BaseModel):
	timestamp: str
	affected_assets: list
	compromised_data: list
	severity: Severity
	user_accounts_involved: list

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
	return JSONResponse(
		status_code = 500,
		content = { "analysis": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/intelligence/analysis", status_code = 200)
async def analysis(data: Data):
	resultOfCheck = incidentIncludesThisSystem(data)
	result = "OK" if resultOfCheck else "NOT OK"
	return { "analysis": "success", "result": result }
