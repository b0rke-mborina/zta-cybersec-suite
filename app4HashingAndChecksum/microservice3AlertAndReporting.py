from fastapi import FastAPI
from pydantic import BaseModel, model_validator, validator
import datetime
import json
from .utilityFunctions import storeReport


app = FastAPI()


class Data(BaseModel):
	timestamp: str
	logger_source: int
	user_id: int
	data: str
	checksum: str
	error_message: str

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

@app.post("/hashing/reporting", status_code = 200)
async def reporting(data: Data):
	await storeReport(data, "app4Reports.db")
	return { "reporting": "success" }
