from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
from enum import Enum
from .utilityFunctions import getData, isStringValid, saveData, sendRequest


app = FastAPI()


class AuthType(str, Enum):
	API_KEY = "api_key"
	OAUTH2_TOKEN = "oauth2_token"
	JWT = "jwt"

class DataInfo(BaseModel):
	auth_type: AuthType
	token_key: str
	user_id: int = None

	class Config:
		use_enum_values = True

	@validator("token_key")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataNew(BaseModel):
	auth_type: AuthType
	token_key: str
	expires: str
	user_id: int = None
	secret: str = None

	class Config:
		use_enum_values = True

	@validator("expires")
	def validateISO8601ExpiresTimestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v

	@validator("token_key", "secret")
	def validateAndSanitizeString(cls, v, field):
		allowNoneOrEmpty = False if field.name == "token_key" else True
		isValid = isStringValid(v, allowNoneOrEmpty, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
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
		"http://127.0.0.1:8080/zta/governance",
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

