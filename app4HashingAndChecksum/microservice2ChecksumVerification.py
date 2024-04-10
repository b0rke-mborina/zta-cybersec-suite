from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum
from .utilityFunctions import sendRequest, verifyChecksum


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

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now().isoformat(),
		"level": "INFO",
		"logger_source": 2,
		"user_id": 1,
		"request": str(request),
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
async def verification(data: Data):
	isHashValid = verifyChecksum(data.data, data.algorithm.value, data.checksum)
	currentTime = datetime.datetime.now(datetime.timezone.utc).isoformat()
	response = { "verification": "success", "is_checksum_valid": 1 if isHashValid else 0 }

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
				"error_message": "Hash Is not valid."
			}
		)
		if reportingResult[0].get("reporting") != "success":
			raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8033/hashing/logging",
		{
			"timestamp": currentTime,
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": "",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
