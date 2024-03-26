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
	tag: str = None
	nonce: str = None

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

def validateTagAndNonce(data):
	if data.algorithm == Algorithm.AES and data.tag is None:
		raise RequestValidationError('Tag is required for AES algorithm')
	if data.algorithm == Algorithm.AES and data.nonce is None:
		raise RequestValidationError('Nonce is required for AES algorithm')

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 1,
		"user_id": 1,
		"request": str(request),
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
async def decryption(data: Data):
	validateTagAndNonce(data)

	plaintext = decrypt(data.algorithm.value, data.ciphertext, data.key, data.tag, data.nonce)
	print("plaintext")
	print(plaintext)
	if plaintext is None:
		raise RequestValidationError("Ciphertext not encoded in base64.")
	
	response = { "decryption": "success", "ciphertext": plaintext }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8003/cryptography/logging",
		{
			"timestamp": datetime.datetime.now().isoformat(),
			"level": "INFO",
			"logger_source": 2,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)

	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
