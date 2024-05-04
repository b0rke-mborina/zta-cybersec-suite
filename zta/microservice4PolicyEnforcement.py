from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json


app = FastAPI()


class Data(BaseModel):
	user_role: int
	logger_source: int
	current_app_id: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "policy": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/policy")
async def policy(data: Data):
	return { "policy": "success" }
