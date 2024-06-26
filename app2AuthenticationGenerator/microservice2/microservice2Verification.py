from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import datetime
import os
from utilityFunctions import getAuthData, isStringValid, sendRequest, verifyAPIKey, verifyOAuth2, verifyJWT


app = FastAPI()


class DataAPIKey(BaseModel):
	api_key: str

	@validator("api_key")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9]{32}$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataOAuth2Token(BaseModel):
	oauth2_token: str

	@validator("oauth2_token")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9_-]+$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

class DataJWT(BaseModel):
	jwt: str

	@validator("jwt")
	def validateAndSanitizeString(cls, v):
		isValid = isStringValid(v, False, r'^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}$')
		
		if not isValid:
			raise RequestValidationError("String is not valid.")
		
		return v

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 22,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
		"response": "__NULL__",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}".translate(str.maketrans("\"'{}:", "_____"))
	}
	await sendRequest("post", os.getenv("URL_LOGGING_MICROSERVICE"), dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "verification": "failure", "error_message": "Input invalid." },
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
		content = { "verification": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/verify/api-key")
async def verificatorAPIKey(request: Request, data: DataAPIKey):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 22
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")
	currentTime = datetime.datetime.now(datetime.timezone.utc)

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_type": "api_key",
				"token_key": data.api_key
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	encryptedData = orchestrationAutomationResult[0].get("data")

	keyResult = await sendRequest(
		"get",
		os.getenv("URL_STORAGE_MICROSERVICE_INFO"),
		{
			"auth_type": encryptedData["auth_type"],
			"token_key": encryptedData["token_key"]
		}
	)
	if keyResult[0].get("getting_info") != "success":
		raise HTTPException(500)

	verificationResult = verifyAPIKey(keyResult[0].get("info"), currentTime)
	response = { "verification": "success", "is_valid": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		os.getenv("URL_LOGGING_MICROSERVICE"),
		{
			"timestamp": currentTime.isoformat(),
			"level": "INFO",
			"logger_source": 22,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
			"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response

@app.get("/auth-generator/verify/oauth2")
async def verificatorOAuth2(request: Request, data: DataOAuth2Token):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 22
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")
	currentTime = datetime.datetime.now(datetime.timezone.utc)

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_type": "oauth2_token",
				"token_key": data.oauth2_token
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	encryptedData = orchestrationAutomationResult[0].get("data")

	tokenResult = await sendRequest(
		"get",
		os.getenv("URL_STORAGE_MICROSERVICE_INFO"),
		{
			"auth_type": encryptedData["auth_type"],
			"token_key": encryptedData["token_key"],
			"user_id": userId
		}
	)
	if tokenResult[0].get("getting_info") != "success":
		raise HTTPException(500)

	verificationResult = verifyOAuth2(tokenResult[0].get("info"), currentTime, userId)
	response = { "verification": "success", "is_valid": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		os.getenv("URL_LOGGING_MICROSERVICE"),
		{
			"timestamp": currentTime.isoformat(),
			"level": "INFO",
			"logger_source": 22,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
			"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response

@app.get("/auth-generator/verify/jwt")
async def verificatorJWT(request: Request, data: DataJWT):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		os.getenv("URL_TUNNELLING_MICROSERVICE"),
		{
			"auth_data": authData,
			"auth_source": 22
		}
	)
	if tunnellingResult[0].get("tunnelling") != "success":
		raise HTTPException(500)
	if not tunnellingResult[0].get("is_authorized"):
		raise RequestValidationError("User not allowed.")
	
	userId = tunnellingResult[0].get("user_id")
	currentTime = datetime.datetime.now(datetime.timezone.utc)

	orchestrationAutomationResult = await sendRequest(
		"get",
		os.getenv("URL_OA_MICROSERVICE_ENCRYPTION"),
		{
			"data": {
				"auth_type": "jwt",
				"token_key": data.jwt
			}
		}
	)
	if orchestrationAutomationResult[0].get("encryption") != "success":
		raise HTTPException(500)
	encryptedData = orchestrationAutomationResult[0].get("data")

	tokenResult = await sendRequest(
		"get",
		os.getenv("URL_STORAGE_MICROSERVICE_INFO"),
		{
			"auth_type": encryptedData["auth_type"],
			"token_key": encryptedData["token_key"],
			"user_id": userId
		}
	)
	if tokenResult[0].get("getting_info") != "success":
		raise HTTPException(500)
	
	verificationResult = verifyJWT(data.jwt, tokenResult[0].get("info"), currentTime, userId)
	response = { "verification": "success", "is_valid": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		os.getenv("URL_LOGGING_MICROSERVICE"),
		{
			"timestamp": currentTime.isoformat(),
			"level": "INFO",
			"logger_source": 22,
			"user_id": userId,
			"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
			"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
			"error_message": "__NULL__"
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
