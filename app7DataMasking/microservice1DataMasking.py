from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from .utilityFunctions import getAuthData, maskData, sendRequest, checkData


app = FastAPI()


class DataMask(BaseModel):
	dataset: str
	data: list

class DataUnmask(BaseModel):
	dataset: str

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 1, # PLACEHOLDER
		"user_id": 1, # PLACEHOLDER
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
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
			"auth_source": 1 # PLACEHOLDER
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")

	checkData(data.data)
	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8062/data/access-control",
		{
			"user_id": 1, # PLACEHOLDER
			"role": "user" # PLACEHOLDER
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)

	maskedData = maskData(data.data)
	print(maskedData)
	response = { "masking": "success", "data": maskedData }

	storageResult = await sendRequest(
		"post",
		"http://127.0.0.1:8061/data/store",
		{
			"dataset": data.dataset,
			"data_original": data.data,
			"data_masked": maskedData
		}
	)
	if storageResult[0].get("storage") != "success":
		raise HTTPException(500)
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8063/data/logging",
		{
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"level": "INFO",
			"logger_source": 1, # PLACEHOLDER
			"user_id": 1, # PLACEHOLDER
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
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
			"auth_source": 1 # PLACEHOLDER
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")

	accessControlResult = await sendRequest(
		"get",
		"http://127.0.0.1:8062/data/access-control",
		{
			"user_id": 1, # PLACEHOLDER
			"role": "user" # PLACEHOLDER
		}
	)
	if accessControlResult[0].get("access_control") != "success" or not accessControlResult[0].get("is_allowed"):
		raise HTTPException(500)

	storageResult = await sendRequest(
		"get",
		"http://127.0.0.1:8061/data/retrieve",
		{
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
			"logger_source": 1, # PLACEHOLDER
			"user_id": 1, # PLACEHOLDER
			"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
