from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import sendRequest, encrypt
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
	plaintext: str
	key: str = None

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

@app.get("/cryptography/encrypt", status_code = 200)
async def encryption(data: Data):
	# print(data)

	link1 = "http://127.0.0.1:8004/cryptography/logging"
	# link2 = "http://127.0.0.1:8003/cryptography/key/get"
	# link3 = "http://127.0.0.1:8003/cryptography/key/store"

	data1 = {
		"timestamp": "2024-03-17",
		"level": "INFO",
		"logger_source": 1,
		"user_id": 1,
		"request": str(data),
		"error_message": ""
	}

	"""data2 = {
		"user_id": 11
	}

	data3 = {
		"user_id": 11,
		"key": data.key
	}"""

	result1 = await sendRequest("post", link1, data1)
	print("Res 1:")
	print(result1)

	if result1[0].get("logging") != "success":
		raise HTTPException(500)

	"""result2 = await sendRequest("get", link2, data2)
	print("Res 2:")
	print(result2)

	if result2[0].get("key_management") != "success":
		raise HTTPException(500)

	result3 = await sendRequest("post", link3, data3)
	print("Res 2:")
	print(result3) # """"""

	if result3[0].get("key_management") != "success":
		raise HTTPException(500)"""
	
	ciphertext = encrypt(data.algorithm, data.plaintext, data.key)

	return { "encryption": "success", "ciphertext": ciphertext }
