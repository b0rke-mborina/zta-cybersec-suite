from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, model_validator
import datetime
from .utilityFunctions import decryptData, encryptData, hashData, sendRequest


app = FastAPI()


class DataCryptography(BaseModel):
	data: dict

class DataHashing(BaseModel):
	data: str

@app.exception_handler(Exception)
async def exceptionHandler(request, exc):
	dataForMonitoringUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "INFO",
		"logger_source": 6,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"ZTA error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8087/zta/monitoring", dataForMonitoringUnsuccessfulRequest)

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
