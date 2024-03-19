from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .utilityFunctions import task
from enum import Enum


app = FastAPI()


class Algorithm(str, Enum):
	TripleDES = "TripleDES"
	AES = "AES"
	RSA = "RSA"
	Blowfish = "Blowfish"
	Twofish = "Twofish"

class Data(BaseModel):
	algorithm: Algorithm
	plaintext: str
	key: str = None

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
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
	print(data)

	link1 = "http://127.0.0.1:8004/cryptography/logging"
	link2 = "http://127.0.0.1:8003/cryptography/key/get"
	link3 = "http://127.0.0.1:8003/cryptography/key/store"

	data1 = {}
	data1["timestamp"] = "2024-03-17"
	data1["level"] = "INFO"
	data1["logger_source"] = 1
	data1["user_id"] = 1
	data1["request"] = "something"
	data1["error_message"] = "this is fine"

	data2 = {}
	data2["user_id"] = 11

	data3 = {}
	data3["user_id"] = 11
	data3["key"] = "HERE_GOES_KEY"

	result1 = await task("get", link1, data1)
	print("Res 1:")
	print(result1)

	if result1[0].get("logging") != "success":
		raise HTTPException(500)

	result2 = await task("get", link2, data2)
	print("Res 2:")
	print(result2)

	if result2[0].get("key_management") != "success":
		raise HTTPException(500)

	result3 = await task("post", link3, data3)
	print("Res 2:")
	print(result3) # """"""

	if result3[0].get("key_management") != "success":
		raise HTTPException(500)

	return { "encryption": "success", "ciphertext": "HERE_GOES_PLAINTEXT" }
