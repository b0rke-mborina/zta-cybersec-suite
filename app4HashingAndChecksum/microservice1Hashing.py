from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum
from .utilityFunctions import hashData, sendRequest


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
	await sendRequest("post", "http://127.0.0.1:8034/hashing/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "hashing": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "hashing": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/hashing/hash", status_code = 200)
async def hashing(data: Data):
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
	if policyResult[0].get("is_data_ok") != 1:
		raise RequestValidationError("Password requirements not fulfilled.")

	hash = hashData(data.data, data.algorithm.value)
	response = { "hashing": "success", "hash": hash }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8034/hashing/logging",
		{
			"timestamp": currentTime,
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
