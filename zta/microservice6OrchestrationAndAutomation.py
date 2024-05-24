from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from .utilityFunctions import decryptData, encryptData, hashData, isStringValid, sendRequest


app = FastAPI()


class DataCryptography(BaseModel):
	data: dict
	
	@validator("data")
	def validateAndSanitizeDict(cls, v):
		for key, value in v.items():
			if isinstance(value, str):
				if not isStringValid(value, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$'):
					raise RequestValidationError("String is not valid.")
		
		return v

class DataHashing(BaseModel):
	data: str
	
	@validator("data")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "FATAL",
				"logger_source": 6,
				"user_id": 0, # placeholder value is used because user is not important
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": "",
				"error_message": f"ZTA error. {exc}"
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8080/zta/governance",
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
async def encryption(data: DataCryptography):
	encryptedData = encryptData(data.data)
	return { "encryption": "success", "data": encryptedData }

@app.get("/zta/decrypt")
async def decryption(data: DataCryptography):
	decryptedData = decryptData(data.data)
	return { "decryption": "success", "data": decryptedData }

@app.get("/zta/hash")
async def decryption(data: DataHashing):
	hashedData = hashData(data.data)
	return { "hashing": "success", "data": hashedData }
