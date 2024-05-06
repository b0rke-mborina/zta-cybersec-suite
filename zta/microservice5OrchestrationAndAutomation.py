from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json


app = FastAPI()


class Data(BaseModel):
	incident: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "orchestration_automation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/orchestration")
async def orchestration(data: Data):
	return { "orchestration": "success" }

@app.get("/zta/automation")
async def automation(data: Data):
	return { "automation": "success" }
