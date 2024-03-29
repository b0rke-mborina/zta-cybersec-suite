from fastapi import FastAPI
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
	user_id: int
	auth_type: AuthType
	token_key: str

class DataNew(BaseModel):
	user_id: int
	auth_type: AuthType
	token_key: str
	expires: str
	secret: str

	@validator("expires")
	def validateISO8601ExpiresTimestamp(cls, v):
		try:
			datetime.datetime.fromisoformat(v)
		except ValueError:
			raise ValueError("Timestamp must be in ISO 8601 format")
		return v
	
	"""@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)"""

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "logging": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/data-info")
async def dataGet(data: DataInfo):
	authData = await getData(data.user_id, data.auth_type.value, data.token_key)
	return { "getting_info": "success", "info": authData }

@app.get("/auth-generator/data-new")
async def dataSave(data: DataNew):
	await saveData(data.user_id, data.auth_type.value, data.token_key, data.expires, data.secret)
	return { "saving_info": "success" }

