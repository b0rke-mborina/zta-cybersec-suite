from fastapi import FastAPI
from pydantic import BaseModel, model_validator, validator
import datetime
import json
from enum import Enum


app = FastAPI()


class Severity(str, Enum):
	LOW = "low"
	MEDIUM = "medium"
	HIGH = "high"

class Incident(BaseModel):
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

class Data(BaseModel):
	incident: Incident
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.get("/intelligence/analysis")
async def analysis(data: Data):
	return { "analysis": "success" }
