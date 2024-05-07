from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import checkIfPossibleDosAtack, getAuthData, handleAuthorization


app = FastAPI()


class Data(BaseModel):
	headers: dict
	
	@model_validator(mode='before')
	@classmethod
	def to_py_dict(cls, data):
		return json.loads(data)

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "tunnelling": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/tunnelling")
async def tunnelling(data: Data):
	(authType, authData) = getAuthData(data.headers)
	isAuthorized = await handleAuthorization(authType, authData)
	isPossibleDosAtack = await checkIfPossibleDosAtack()
	return { "tunnelling": "success", "is_authorized": isAuthorized and not isPossibleDosAtack }
