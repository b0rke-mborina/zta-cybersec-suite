from fastapi import FastAPI
from pydantic import BaseModel, model_validator, validator
from .utilityFunctions import getData, saveData
import datetime
import json
from enum import Enum


app = FastAPI()


class AuthType(str, Enum):
	KEY = "key"
	TOKEN = "token"

class DataInfo(BaseModel):
	user_id: int
	auth_type: AuthType
	token_key: str

class DataNew(BaseModel):
	user_id: int
	auth_type: AuthType
	token_key: str
	secret: str
	expires: str

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

@app.get("/auth-generator/data-info")
async def verificatorAPIKey(data: DataInfo):
	authData = await getData(data.user_id, data.auth_type, data.token_key)
	return { "getting_info": "success", "info": authData }

@app.get("/auth-generator/data-new")
async def verificatorOAuth2(data: DataNew):
	await saveData()
	return { "saving_info": "success" }

