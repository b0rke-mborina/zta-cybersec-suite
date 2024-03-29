from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator, validator
from .utilityFunctions import getData, saveData
import datetime
import json
from enum import Enum


app = FastAPI()


class AuthType(str, Enum):
	API_KEY = "api_key"
	OAUTH2_TOKEN = "oauth2_token"
	JWT = "jwt"

class DataInfo(BaseModel):
	auth_type: AuthType
	token_key: str
	user_id: int = None

class DataNew(BaseModel):
	auth_type: AuthType
	token_key: str
	expires: str
	user_id: int = None
	secret: str = None

	@validator("expires")
	def validateISO8601ExpiresTimestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

def validateInfoUserId(data):
	print(data.auth_type)
	if data.auth_type in [AuthType.OAUTH2_TOKEN, AuthType.JWT] and data.user_id is None:
		raise RequestValidationError('User id is required for OAuth2 and JWT auth type')

def validateSaveUserIdAndSecret(data):
	print(data.auth_type)
	if data.auth_type in [AuthType.OAUTH2_TOKEN, AuthType.JWT] and data.user_id is None:
		raise RequestValidationError('User id is required for OAuth2 and JWT auth type')
	if data.auth_type == AuthType.JWT and data.secret is None:
		raise RequestValidationError('Secret is required for JWT auth type')

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "logging": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/data-info")
async def dataGet(data: DataInfo):
	validateInfoUserId(data)

	authData = await getData(data.auth_type.value, data.token_key, data.user_id)
	return { "getting_info": "success", "info": authData }

@app.post("/auth-generator/data-new")
async def dataSave(data: DataNew):
	validateSaveUserIdAndSecret(data)

	await saveData(data.auth_type.value, data.token_key, data.expires, data.user_id, data.secret)
	return { "saving_info": "success" }

