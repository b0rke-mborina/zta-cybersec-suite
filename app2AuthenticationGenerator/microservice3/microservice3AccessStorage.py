from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, validator
import datetime
import os
from enum import Enum
from utilityFunctions import getData, isStringValid, saveData, sendRequest


app = FastAPI()


class AuthType(str, Enum):
	API_KEY = "tEq0nzMfSsQ="
	OAUTH2_TOKEN = "S52Z0ZDeDS7mKe43X+Y2sg=="
	JWT = "MKgIfWpSwwI="

class DataInfo(BaseModel):
	auth_type: AuthType
	token_key: str
	user_id: str = None

	class Config:
		use_enum_values = True

	@field_validator("token_key", "user_id")
	def validateAndSanitizeString(cls, v, info):
		allowNoneOrEmpty = True if info.field_name == "user_id" else False
		isValid = isStringValid(v, allowNoneOrEmpty, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataNew(BaseModel):
	auth_type: AuthType
	token_key: str
	expires: str
	user_id: str = None
	secret: str = None

	class Config:
		use_enum_values = True

	@validator("expires")
	def validateISO8601Timestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

	@field_validator("token_key", "user_id", "secret")
	def validateAndSanitizeString(cls, v, info):
		allowNoneOrEmpty = True if info.field_name == "secret" or info.field_name == "user_id" else False
		isValid = isStringValid(v, allowNoneOrEmpty, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')

		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

def validateInfoUserId(data):
	print(data.auth_type)
	if data.auth_type in ["oauth2_token", "jwt"] and data.user_id is None:
		raise RequestValidationError('User id is required for OAuth2 and JWT auth type')

def validateSaveUserIdAndSecret(data):
	print(data.auth_type)
	if data.auth_type in ["oauth2_token", "jwt"] and data.user_id is None:
		raise RequestValidationError('User id is required for OAuth2 and JWT auth type')
	if data.auth_type == "jwt" and data.secret is None:
		raise RequestValidationError('Secret is required for JWT auth type')

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
		content = { "access_storage": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/data-info")
async def dataGet(data: DataInfo):
	validateInfoUserId(data)

	authData = await getData(data.auth_type, data.token_key, data.user_id)
	return { "getting_info": "success", "info": authData }

@app.post("/auth-generator/data-new")
async def dataSave(data: DataNew):
	validateSaveUserIdAndSecret(data)

	await saveData(data.auth_type, data.token_key, data.expires, data.user_id, data.secret)
	return { "saving_info": "success" }

