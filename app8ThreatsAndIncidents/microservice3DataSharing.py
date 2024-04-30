from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import getThreats, storeThreat


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class DataReport(BaseModel):
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
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

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
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "data_sharing": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/intelligence/report", status_code = 200)
async def reporting(data: DataReport):
	await storeThreat("app8Data.db", 1, data)
	return { "reporting": "success" }

@app.get("/intelligence/retrieve", status_code = 200)
async def retrieval(data: DataRetrieve):
	threats = await getThreats("app8Data.db", data.time_from, data.time_to, data.severity)
	return { "retrieval": "success", "data": threats }
