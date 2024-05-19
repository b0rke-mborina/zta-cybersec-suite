from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import getThreats, sendRequest, storeThreat


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class DataIncident(BaseModel):
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
	
	class Config:
		use_enum_values = True

	@validator("timestamp")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

class DataThreats(BaseModel):
	time_from: str
	time_to: str
	severity: Severity
	
	class Config:
		use_enum_values = True

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

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "data_sharing": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/intelligence/incident", status_code = 200)
async def incident(data: DataIncident):
	analysisResult = await sendRequest(
		"get",
		"http://127.0.0.1:8073/intelligence/analysis",
		{
			"timestamp": data.timestamp,
			"affected_assets": data.affected_assets,
			"compromised_data": data.compromised_data,
			"severity": data.severity,
			"user_accounts_involved": data.user_accounts_involved
		}
	)
	if analysisResult[0].get("analysis") != "success" or not analysisResult[0].get("is_ok"):
		raise HTTPException(500)
	
	await storeThreat("app8Data.db", 1, data)
	return { "incident": "success" }

@app.get("/intelligence/threats", status_code = 200)
async def threats(data: DataThreats):
	threats = await getThreats("app8Data.db", data.time_from, data.time_to, data.severity)
	return { "threats": "success", "data": threats }
