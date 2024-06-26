from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import asyncio
import datetime
import os
from enum import Enum
from .utilityFunctions import encryptBlowfish, encryptData, getThreats, isStringValid, sendRequest, storeThreat


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class DataIncident(BaseModel):
	user_id: str
	username: str
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

	@field_validator("user_id", "username")
	def validateAndSanitizeString(cls, v, info):
		regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' if info.field_name == "user_id" else r'^[a-zA-Z0-9._-]{3,20}$'
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
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
					return v
				else:
					raise RequestValidationError("Request not valid.")
		
		return v

class DataThreats(BaseModel):
	time_from: str
	time_to: str
	severity: Severity
	
	class Config:
		use_enum_values = True

	@validator("time_from", "time_to")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Time value must be in ISO 8601 format.")
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
		content = { "data_sharing": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/intelligence/incident", status_code = 200)
async def incident(data: DataIncident):
	dataForEncryption = data.model_dump()
	userId = dataForEncryption["user_id"]
	del dataForEncryption["user_id"]
	timestamp = dataForEncryption["timestamp"]
	del dataForEncryption["timestamp"]

	dataForStorage = encryptData(dataForEncryption)
	dataForStorage["user_id"] = userId
	dataForStorage["timestamp"] = timestamp

	tasks = [
		sendRequest(
			"get",
			os.getenv("URL_ANALYSIS_MICROSERVICE"),
			{
				"user_id": data.user_id,
				"username": data.username,
				"timestamp": data.timestamp,
				"affected_assets": data.affected_assets,
				"compromised_data": data.compromised_data,
				"severity": data.severity,
				"user_accounts_involved": data.user_accounts_involved
			}
		),
		storeThreat("app8Data.db", data.user_id, dataForStorage)
	]
	
	results = await asyncio.gather(*tasks)
	if results[0][0].get("analysis") != "success" or not results[0][0].get("is_ok"):
		raise HTTPException(500)
	
	return { "incident": "success" }

@app.get("/intelligence/threats", status_code = 200)
async def threats(data: DataThreats):
	severity = encryptBlowfish("severity", data.severity)
	threats = await getThreats("app8Data.db", data.time_from, data.time_to, severity)

	return { "threats": "success", "data": threats }
