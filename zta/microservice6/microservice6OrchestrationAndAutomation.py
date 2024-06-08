from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
import os
from utilityFunctions import decryptData, encryptData, hashData, isStringValid, sendRequest


app = FastAPI()


class DataEncrypt(BaseModel):
	data: dict
	
	@validator("data")
	def validateAndSanitizeDict(cls, v):
		for key, value in v.items():
			if isinstance(value, str):
				if not isStringValid(value, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$'):
					raise RequestValidationError("String is not valid.")
		
		return v

class DataDecrypt(BaseModel):
	data: dict
	
	@validator("data")
	def validateAndSanitizeDict(cls, v):
		for key, value in v.items():
			if isinstance(value, str):
				if not isStringValid(value, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'): # base64 regex
					raise RequestValidationError("String is not valid.")
		
		return v

class DataHashing(BaseModel):
	data: str
	
	@validator("data")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-\s]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	tasks = [
		sendRequest(
			"post",
			os.getenv("URL_MONITORING_MICROSERVICE"),
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 6,
				"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user is not important
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": "__NULL__",
				"error_message": f"ZTA error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
			}
		),
		sendRequest(
			"post",
			os.getenv("URL_GOVERNANCE_MICROSERVICE"),
			{
				"problem": "total_system_failure"
			}
		)
	]
	await asyncio.gather(*tasks)

	return JSONResponse(
		status_code = 500,
		content = { "orchestration_automation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/zta/encrypt")
async def encryption(data: DataEncrypt):
	encryptedData = encryptData(data.data)
	return { "encryption": "success", "data": encryptedData }

@app.get("/zta/decrypt")
async def decryption(data: DataDecrypt):
	decryptedData = decryptData(data.data)
	return { "decryption": "success", "data": decryptedData }

@app.get("/zta/hash")
async def decryption(data: DataHashing):
	hashedData = hashData(data.data)
	return { "hashing": "success", "data": hashedData }
