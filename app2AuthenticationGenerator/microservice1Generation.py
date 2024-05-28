import asyncio
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import datetime
from .utilityFunctions import getAuthData, sendRequest, generateAPIKey, generateOAuth2, generateJWT


app = FastAPI()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
	dataForLoggingUnsuccessfulRequest = {
		"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
		"level": "ERROR",
		"logger_source": 21,
		"user_id": "35oIObfdlDo=", # placeholder value 0 is used because user will not be authenticated
		"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
		"response": "",
		"error_message": f"Unsuccessful request due to a Request Validation error. {exc}"
	}
	await sendRequest("post", "http://127.0.0.1:8013/auth-generator/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "generation": "failure", "error_message": "Input invalid." },
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
		content = { "generation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/generate/api-key")
async def generatorAPIKey(request: Request):
	authData = getAuthData(request.headers)
	tunnellingResult = await sendRequest(
		"get",
		"http://127.0.0.1:8085/zta/tunnelling",
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
	print(apiKey)
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	apiKeyData = {
		"auth_type": "api_key",
		"token_key": apiKey,
		"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
	}

	response = { "generation": "success", "api_key": apiKey }

	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8012/auth-generator/data-new",
			apiKeyData
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8013/auth-generator/logging",
			{
				"timestamp": currentTime.isoformat(),
				"level": "INFO",
				"logger_source": 21,
				"user_id": userId,
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": str(response),
				"error_message": ""
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
		"http://127.0.0.1:8085/zta/tunnelling",
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
	print(oauth2Token)
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	oauth2TokenData = {
		"auth_type": "oauth2_token",
		"token_key": oauth2Token,
		"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
		"user_id": userId
	}

	response = { "generation": "success", "oauth2_token": oauth2Token }

	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8012/auth-generator/data-new",
			oauth2TokenData
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8013/auth-generator/logging",
			{
				"timestamp": currentTime.isoformat(),
				"level": "INFO",
				"logger_source": 21,
				"user_id": userId,
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": str(response),
				"error_message": ""
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
		"http://127.0.0.1:8085/zta/tunnelling",
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
	print(jwToken)
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	jwtokenData = {
		"auth_type": "jwt",
		"token_key": jwToken,
		"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
		"user_id": userId,
		"secret": "SECRET_KEY_PLACEHOLDER" # PLACEHOLDER
	}

	response = { "generation": "success", "jwtoken": jwToken }

	tasks = [
		sendRequest(
			"post",
			"http://127.0.0.1:8012/auth-generator/data-new",
			jwtokenData
		),
		sendRequest(
			"post",
			"http://127.0.0.1:8013/auth-generator/logging",
			{
				"timestamp": currentTime.isoformat(),
				"level": "INFO",
				"logger_source": 21,
				"user_id": userId,
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": str(response),
				"error_message": ""
			}
		)
	]
	results = await asyncio.gather(*tasks)
	if results[0][0].get("saving_info") != "success" or results[1][0].get("logging") != "success":
		raise HTTPException(500)
	
	return response
