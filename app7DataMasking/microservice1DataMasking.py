from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import asyncio
import datetime
from .utilityFunctions import getAuthData, isStringValid, maskData, sendRequest, checkData


app = FastAPI()


class DataMask(BaseModel):
	dataset: str
	data: list

	@validator("dataset")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

	@validator("data")
	def validateAndSanitizeString(cls, v):
		for l in v:
			for dataValue in l:
				if isinstance(dataValue, str):
					isValid = isStringValid(dataValue, False, r'^[A-Za-z0-9+/=.,!@#$%^&*()_+\-]*$')
					if not isValid:
						raise RequestValidationError("String is not valid.")
		return v

class DataUnmask(BaseModel):
	dataset: str

	@validator("dataset")
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
		"logger_source": 71,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", "http://127.0.0.1:8063/data/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "data_masking": "failure", "error_message": "Input invalid." },
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
		content = { "data_masking": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/data/mask")
async def masking(request: Request, data: DataMask):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 71
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")
	userRole = tunnellingResult[0].get("user_role")

	checkData(data.data)
	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8062/data/access-control",
		{
			"user_id": userId,
			"role": userRole
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)

	maskedData = maskData(data.data)
	print(maskedData)
	response = { "masking": "success", "data": maskedData }

	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8061/data/store",
			{
				"user_id": userId,
				"dataset": data.dataset,
				"data_original": data.data,
				"data_masked": maskedData
			}
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8063/data/logging",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 71,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}[]:", "_______")),
				"response": str(response).translate(str.maketrans("\"'{}[]:", "_______")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("storage") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)
	
	return response

@app.get("/data/unmask")
async def unmasking(request: Request, data: DataUnmask):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
		{
			"auth_data": authData,
			"auth_source": 71
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
		"http://127.0.0.1:8062/data/access-control",
		{
			"user_id": userId,
			"role": userRole
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)

	storageResult = await sendRequest(
		"get",
		"http://127.0.0.1:8061/data/retrieve",
		{
			"user_id": userId,
			"dataset": data.dataset
		}
	)
	if storageResult[0].get("retrieval") != "success":
		raise HTTPException(500)
	data = storageResult[0].get("data")
	response = { "unmasking": "success", "data": data }
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8063/data/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 71,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}[]:", "_______")),
			"response": str(response).translate(str.maketrans("\"'{}[]:", "_______")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
