from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import datetime
from enum import Enum
from .utilityFunctions import incidentIncludesThisSystem, isStringValid, sendRequest


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class Data(BaseModel):
	user_id: str
	username: str
	timestamp: str
	affected_assets: list
	compromised_data: list
	severity: Severity
	user_accounts_involved: list
	
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

	@validator("affected_assets", "compromised_data", "user_accounts_involved")
	def validateAndSanitizeList(cls, v):
		for item in v:
			if isinstance(item, str):
				isValid = isStringValid(item, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$')
				if not isValid:
					raise RequestValidationError("String is not valid.")
				return v
			else:
				raise RequestValidationError("Request not valid.")

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "analysis": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/intelligence/analysis", status_code = 200)
async def analysis(data: Data):
	isThisSystemIncluded = incidentIncludesThisSystem(data)
	isOK = not isThisSystemIncluded

	if isThisSystemIncluded:
		governanceResult = await sendRequest(
			"post",
			"http://127.0.0.1:8080/zta/governance",
			{
				"problem": "security_breach",
				"user_id": data.user_id
			}
		)
		if governanceResult[0].get("governance") != "success":
			raise HTTPException(500)

	return { "analysis": "success", "is_ok": isOK }
