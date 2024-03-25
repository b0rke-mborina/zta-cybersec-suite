from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from .utilityFunctions import sendRequest, decrypt
import datetime
from enum import Enum


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

	@validator('key')
	def validate_key(cls, v, values, **kwargs):
		algorithm = values.get('algorithm')
		if algorithm == Algorithm.DES and len(v) != 8:
			raise ValueError('Key must be 8 characters long for DES algorithm')
		elif algorithm == Algorithm.TripleDES and len(v) != 24:
			raise ValueError('Key must be 24 characters long for TripleDES algorithm')
		elif algorithm == Algorithm.AES and len(v) != 16:
			raise ValueError('Key must be 16 characters long for AES algorithm')
		elif algorithm == Algorithm.RSA and len(v) not in [1024, 2048, 3072]:
			raise ValueError('Key must be 1024, 2048, or 3072 characters long for RSA algorithm')
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 1,
		"user_id": 1,
		"request": str(request),
		"error_message": "Unsuccessful request due to a Request Validation error."
	}
	await sendRequest("post", "http://127.0.0.1:8004/cryptography/logging", dataForLoggingUnsuccessfulRequest)

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

@app.get("/cryptography/decrypt", status_code = 200)
async def decryption(data: Data):
	plaintext = decrypt(data.algorithm.value, data.ciphertext, data.key)
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8004/cryptography/logging",
		{
			"timestamp": "2024-03-17",
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"error_message": ""
		}
	)

	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return { "decryption": "success", "ciphertext": plaintext }
