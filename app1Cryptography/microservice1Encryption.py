from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import sendRequest, encrypt


app = FastAPI()


class Algorithm(str, Enum):
	DES = "DES"
	TripleDES = "TripleDES"
	AES = "AES"
	RSA = "RSA"
	Blowfish = "Blowfish"

class Data(BaseModel):
	algorithm: Algorithm
	plaintext: str
	key: str = None
	key_length: int = None

	class Config:
		use_enum_values = True

	@validator("key")
	def validatorKey(cls, v, values, **kwargs):
		algorithm = values.get("algorithm")
		if algorithm in ["DES", "TripleDES", "AES", "Blowfish"] and v is None:
			raise RequestValidationError('Key is required for DES, TripleDES, AES or Blowfish algorithm')
		
		if algorithm == "DES" and len(v) != 8:
			raise RequestValidationError('Key must be 8 characters long for DES algorithm')
		elif algorithm == "TripleDES" and len(v) != 24:
			raise RequestValidationError('Key must be 24 characters long for TripleDES algorithm')
		elif algorithm == "AES" and len(v) != 16:
			raise RequestValidationError('Key must be 16 characters long for AES algorithm')
		return v

	@validator("key_length")
	def validatorKeyLength(cls, v, values, **kwargs):
		algorithm = values.get('algorithm')
		if algorithm == "RSA" and v not in [1024, 2048, 3072]:
			raise RequestValidationError('Acceptable values for key_length are 1024, 2048, 3072 for RSA algorithm')
		return v

def validateKeyAndKeyLength(data):
	print(data.algorithm)
	if data.algorithm in ["DES", "TripleDES", "AES", "Blowfish"] and data.key is None:
		raise RequestValidationError('Key is required for DES, TripleDES, AES or Blowfish algorithm')
	if data.algorithm == "RSA" and data.key_length is None:
		raise RequestValidationError('Value of key_length is requried for RSA algorithm')

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
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
		content = { "encryption": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "encryption": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/cryptography/encrypt", status_code = 200)
async def encryption(request: Request, data: Data):
	print(request.headers)

	validateKeyAndKeyLength(data)
	
	encryptionResult = encrypt(data.algorithm, data.plaintext, data.key, data.key_length)

	response = {}
	if data.algorithm == Algorithm.RSA:
		response = { "encryption": "success", "ciphertext": encryptionResult[0], "private_key": encryptionResult[1], "public_key": encryptionResult[2] }
	elif data.algorithm == Algorithm.AES:
		response = { "encryption": "success", "ciphertext": encryptionResult[0], "tag": encryptionResult[1], "nonce": encryptionResult[2] }
	else:
		response = { "encryption": "success", "ciphertext": encryptionResult[0] }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8003/cryptography/logging",
		{
			"timestamp": datetime.datetime.now().isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			# improve data for logging
			# enable read data from app and from bruno
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": json.dumps(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
