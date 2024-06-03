from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from enum import Enum
from .utilityFunctions import getAuthData, isStringValid, sendRequest


app = FastAPI()


class Format(str, Enum):
	TXT = "txt"
	BASE64 = "base64"

class DataStore(BaseModel):
	format: Format
	filename: str
	file: str

	class Config:
		use_enum_values = True

	@validator("filename", "file", always = True)
	def validateAndSanitizeString(cls, v, values):
		formatValue = values.get("format")
		fileValue = values.get("file")

		regex = r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$'
		if formatValue == "base64" and v == fileValue:
			regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
		
		isValid = isStringValid(v, False, regex)
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataRetrieve(BaseModel):
	filename: str

	@validator("filename")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 61,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", "http://127.0.0.1:8054/file/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "storage": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def exceptionHandler(request, exc):
	await sendRequest(
		"post",
		"http://127.0.0.1:8080/zta/governance",
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "sharing": "failure", "error_message": "Unexpected error occured." },
	)

@app.post("/file/store")
async def storage(request: Request, data: DataStore):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 61
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")
	userRole = tunnellingResult[0].get("user_role")

	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8053/file/access-control",
		{
			"user_id": userId,
			"role": userRole
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)
	
	response = { "storage": "success" }

	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8051/file/storage",
			{
				"user_id": userId,
				"format": data.format,
				"filename": data.filename,
				"file": data.file
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8054/file/logging",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 61,
				"user_id": userId,
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("storage") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)

	return response

@app.get("/file/retrieve")
async def retrieval(request: Request, data: DataRetrieve):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 61
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")
	userRole = tunnellingResult[0].get("user_role")

	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8053/file/access-control",
		{
			"user_id": userId,
			"role": userRole
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)
	
	retrievalResult = await sendRequest(
		"get",
		"http://127.0.0.1:8051/file/retrieval",
		{
			"user_id": userId,
			"filename": data.filename
		}
	)
	file = retrievalResult[0].get("file")
	if retrievalResult[0].get("retrieval") != "success" and file is not None:
		raise HTTPException(500)
	response = { "storage": "success", "file": file }

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8054/file/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 61,
			"user_id": userId,
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
			"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)

	return response
