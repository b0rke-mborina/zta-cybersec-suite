from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json


app = FastAPI()


class Data(BaseModel):
	problem: int
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "governance": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/governance")
async def governance(data: Data):
	return { "governance": "success" }
