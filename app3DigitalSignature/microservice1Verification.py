from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from enum import Enum
from .utilityFunctions import sendRequest, verifySignature


app = FastAPI()


class HashFunction(str, Enum):
	SHA256 = "sha256"
	SHA512 = "sha512"

class Data(BaseModel):
	public_key: str
	digital_signature: str
	message: str
	hash_function: HashFunction

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
	await sendRequest("post", "http://127.0.0.1:8022/digital-signature/logging", dataForLoggingUnsuccessfulRequest)

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

@app.get("/digital-signature/verify")
async def digitalSignatureVerificator(request: Request, data: Data):
	result = verifySignature(data.public_key, data.digital_signature, data.message, data.hash_function)
	currentTime = datetime.datetime.now(datetime.timezone.utc).isoformat()

	response = { "verification": "success", "is_valid": result }

	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8021/digital-signature/access-control",
		{
			"user_id": 1,
			"role": "user"
		}
	)
	if accessControlResult[0].get("access_control") != "success" or accessControlResult[0].get("is_allowed") != 1:
		raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8022/digital-signature/logging",
		{
			"timestamp": currentTime,
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response

