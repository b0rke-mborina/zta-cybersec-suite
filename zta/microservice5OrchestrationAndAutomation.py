from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import decryptData, encryptData


app = FastAPI()


class Data(BaseModel):
	data: dict
	
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

@app.get("/zta/encrypt")
async def encryption(data: Data):
	encryptedData = encryptData(data.data)
	return { "encryption": "success", "data": encryptedData }

@app.get("/zta/decrypt")
async def decryption(data: Data):
	decryptedData = decryptData(data.data)
	return { "decryption": "success", "data": decryptedData }
