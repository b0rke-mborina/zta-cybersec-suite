from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import getAuthData, sendRequest, decrypt


app = FastAPI()


class Algorithm(str, Enum):
	DES = "DES"
	TripleDES = "TripleDES"
	AES = "AES"
	RSA = "RSA"
	Blowfish = "Blowfish"

class Data(BaseModel):
	algorithm: Algorithm
	ciphertext: str
	key: str
	tag: str = None
	nonce: str = None

	class Config:
		use_enum_values = True

	@validator('key')
	def validate_key(cls, v, values, **kwargs):
		algorithm = values.get('algorithm')
		if algorithm == "DES" and len(v) != 8:
			raise ValueError('Key must be 8 characters long for DES algorithm')
		elif algorithm == "TripleDES" and len(v) != 24:
			raise ValueError('Key must be 24 characters long for TripleDES algorithm')
		elif algorithm == "AES" and len(v) != 16:
			raise ValueError('Key must be 16 characters long for AES algorithm')
		return v

def validateTagAndNonce(data):
	if data.algorithm == "AES" and data.tag is None:
		raise RequestValidationError('Tag is required for AES algorithm')
	if data.algorithm == "AES" and data.nonce is None:
		raise RequestValidationError('Nonce is required for AES algorithm')

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "INFO",
		"logger_source": 1,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8003/cryptography/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "decryption": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "encryption": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/cryptography/decrypt", status_code = 200)
async def decryption(request: Request, data: Data):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 1
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")

	validateTagAndNonce(data)

	plaintext = decrypt(data.algorithm, data.ciphertext, data.key, data.tag, data.nonce)
	if len(plaintext) == 0:
		raise RequestValidationError("Decryption not successful.")
	
	response = { "decryption": "success", "plaintext": plaintext }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8003/cryptography/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 2,
			"user_id": 1,
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": json.dumps(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
