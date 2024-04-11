from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import validatePassword


app = FastAPI()


class Data(BaseModel):
	data: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "policy_management": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/hashing/policy", status_code = 200)
async def reporting(data: Data):
	isPasswordValid = validatePassword(data.data)
	return { "policy_management": "success", "is_data_ok": 1 if isPasswordValid else 0 }
