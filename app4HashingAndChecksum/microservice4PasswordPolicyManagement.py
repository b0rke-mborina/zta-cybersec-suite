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
		content = { "policy_management": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/hashing/policy", status_code = 200)
async def reporting(data: Data):
	isPasswordValid = validatePassword(data.data)
	return { "policy_management": "success", "is_data_ok": isPasswordValid }
