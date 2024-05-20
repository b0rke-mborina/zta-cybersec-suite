from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum
from .utilityFunctions import getAuthData, sendRequest, verifyChecksum


app = FastAPI()


class Algorithm(str, Enum):
	MD5 = "MD5"
	SHA1 = "SHA-1"
	SHA256 = "SHA-256"
	SHA512 = "SHA-512"

class Data(BaseModel):
	data: str
	algorithm: Algorithm
	checksum: str

	class Config:
		use_enum_values = True

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 2,
		"user_id": 1,
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8034/hashing/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "verification": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "verification": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/hashing/verify", status_code = 200)
async def verification(request: Request, data: Data):
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

	isHashValid = verifyChecksum(data.data, data.algorithm, data.checksum)
	currentTime = datetime.datetime.now(datetime.timezone.utc).isoformat()
	response = { "verification": "success", "is_checksum_valid": isHashValid }

	if not isHashValid:
		reportingResult = await sendRequest(
			"post",
			"http://127.0.0.1:8032/hashing/reporting",
			{
				"timestamp": currentTime,
				"logger_source": 2,
				"user_id": 1,
				"data": data.data,
				"checksum": data.checksum,
				"error_message": "Hash is not valid."
			}
		)
		if reportingResult[0].get("reporting") != "success":
			raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8034/hashing/logging",
		{
			"timestamp": currentTime,
			"level": "INFO",
			"logger_source": 2,
			"user_id": 1,
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
