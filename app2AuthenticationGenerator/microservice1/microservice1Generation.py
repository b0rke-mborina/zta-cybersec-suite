from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import asyncio
import datetime
import os
from utilityFunctions import getAuthData, sendRequest, generateAPIKey, generateOAuth2, generateJWT


app = FastAPI()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 21,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", os.getenv("URL_LOGGING_MICROSERVICE"), dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "generation": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	await sendRequest(
		"post",
		os.getenv("URL_GOVERNANCE_MICROSERVICE"),
		{
			"problem": "partial_system_failure"
		}
	)
	
	return JSONResponse(
		status_code = 500,
		content = { "generation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/generate/api-key")
async def generatorAPIKey(request: Request):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 21
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	apiKey = generateAPIKey()
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	response = { "generation": "success", "api_key": apiKey }

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_type": "api_key",
				"token_key": apiKey
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	encryptedData = orchestrationAutomationResult[0].get("data")

	tasks = [
		sendRequest(
			"post",
			os.getenv("URL_STORAGE_MICROSERVICE_NEW"),
			{
				"auth_type": encryptedData["auth_type"],
				"token_key": encryptedData["token_key"],
				"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
			}
		),
		sendRequest(
			"post",
			os.getenv("URL_LOGGING_MICROSERVICE"),
			{
				"timestamp": currentTime.isoformat(),
				"level": "INFO",
				"logger_source": 21,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("saving_info") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)

	return response

@app.get("/auth-generator/generate/oauth2")
async def generatorOAuth2(request: Request):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 21
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	oauth2Token = generateOAuth2()
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	response = { "generation": "success", "oauth2_token": oauth2Token }

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_type": "oauth2_token",
				"token_key": oauth2Token
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	encryptedData = orchestrationAutomationResult[0].get("data")

	tasks = [
		sendRequest(
			"post",
			os.getenv("URL_STORAGE_MICROSERVICE_NEW"),
			{
				"auth_type": encryptedData["auth_type"],
				"token_key": encryptedData["token_key"],
				"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
				"user_id": userId
			}
		),
		sendRequest(
			"post",
			os.getenv("URL_LOGGING_MICROSERVICE"),
			{
				"timestamp": currentTime.isoformat(),
				"level": "INFO",
				"logger_source": 21,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("saving_info") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)

	return response

@app.get("/auth-generator/generate/jwt")
async def generatorJWT(request: Request):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 21
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")

	jwToken = generateJWT(userId)
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	response = { "generation": "success", "jwtoken": jwToken }

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_type": "jwt",
				"token_key": jwToken,
				"secret": "SECRET_KEY_PLACEHOLDER" # PLACEHOLDER
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	encryptedData = orchestrationAutomationResult[0].get("data")

	tasks = [
		sendRequest(
			"post",
			os.getenv("URL_STORAGE_MICROSERVICE_NEW"),
			{
				"auth_type": encryptedData["auth_type"],
				"token_key": encryptedData["token_key"],
				"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
				"user_id": userId,
				"secret": encryptedData["secret"]
			}
		),
		sendRequest(
			"post",
			os.getenv("URL_LOGGING_MICROSERVICE"),
			{
				"timestamp": currentTime.isoformat(),
				"level": "INFO",
				"logger_source": 21,
				"user_id": userId,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": "__NULL__"
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("saving_info") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
