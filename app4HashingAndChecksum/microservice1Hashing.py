from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum
from .utilityFunctions import getAuthData, hashData, sendRequest


app = FastAPI()


class Algorithm(str, Enum):
	MD5 = "MD5"
	SHA1 = "SHA-1"
	SHA256 = "SHA-256"
	SHA512 = "SHA-512"

class Data(BaseModel):
	data: str
	algorithm: Algorithm
	password: bool

	class Config:
		use_enum_values = True

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 41,
		"user_id": 0, # placeholder value is used because user will not be authenticated
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8034/hashing/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "hashing": "failure", "error_message": "Input invalid." },
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
		content = { "hashing": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/hashing/hash", status_code = 200)
async def hashing(request: Request, data: Data):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 41
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")

	currentTime = datetime.datetime.now(datetime.timezone.utc).isoformat()

	policyResult = await sendRequest(
		"get",
		"http://127.0.0.1:8033/hashing/policy",
		{
			"data": data.data
		}
	)
	if policyResult[0].get("policy_management") != "success":
		raise HTTPException(500)
	if policyResult[0].get("is_data_ok"):
		raise RequestValidationError("Password requirements not fulfilled.")

	hash = hashData(data.data, data.algorithm)
	response = { "hashing": "success", "hash": hash }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8034/hashing/logging",
		{
			"timestamp": currentTime,
			"level": "INFO",
			"logger_source": 41,
			"user_id": 1, # PLACEHOLDER
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
