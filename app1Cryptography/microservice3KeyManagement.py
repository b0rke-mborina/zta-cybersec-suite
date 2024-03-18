from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json


app = FastAPI()


class DataGet(BaseModel):
	user_id: int
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data) # """"""

class DataStore(BaseModel):
	user_id: int
	key: str
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "key_management": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/cryptography/key/get", status_code = 200)
async def getKey(data: DataGet):
	print(data)
	return { "key_management": "success", "key": "HERE_GOES_KEY" }

@app.post("/cryptography/key/store", status_code = 200)
async def storeKey(data: DataStore):
	print(data)
	return { "key_management": "success" }
