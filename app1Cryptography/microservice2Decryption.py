from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
import json
from enum import Enum
from .utilityFunctions import getAuthData, isStringValid, sendRequest, decrypt


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

	@validator("ciphertext")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

	@validator("key")
	def validate_key(cls, v, values, **kwargs):
		algorithm = values.get('algorithm')

		regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' if algorithm == "RSA" else r'^[A-Za-z0-9]*$'
		isValid = isStringValid(v, False, regex)
		if not isValid:
			raise RequestValidationError("String is not valid.")

		if algorithm == "DES" and len(v) != 8:
			raise ValueError('Key must be 8 characters long for DES algorithm')
		elif algorithm == "TripleDES" and len(v) != 24:
			raise ValueError('Key must be 24 characters long for TripleDES algorithm')
		elif algorithm == "AES" and len(v) != 16:
			raise ValueError('Key must be 16 characters long for AES algorithm')
		
		return v

def validateTagAndNonce(data):
	if data.algorithm == "AES":
		isValid = isStringValid(data.tag, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		if not isValid:
			raise RequestValidationError("String is not valid.")

		isValid = isStringValid(data.nonce, False, r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
		if not isValid:
			raise RequestValidationError("String is not valid.")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 12,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", "http://127.0.0.1:8003/cryptography/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "decryption": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
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
			"auth_source": 12
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

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
			"logger_source": 12,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
			"response": json.dumps(response).translate(str.maketrans("\"'{}:", "_____")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
