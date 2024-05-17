from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import json
from .utilityFunctions import validatePassword


app = FastAPI()


class Data(BaseModel):
	data: str

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "policy": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/password/policy", status_code = 200)
async def policy(data: Data):
	isPasswordValid = validatePassword(data.data)
	return { "policy": "success", "is_data_ok": isPasswordValid }
