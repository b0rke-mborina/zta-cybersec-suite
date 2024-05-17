from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import datetime
from .utilityFunctions import sendRequest, verifyAPIKey, verifyOAuth2, verifyJWT


app = FastAPI()


class DataAPIKey(BaseModel):
	api_key: str

class DataOAuth2Token(BaseModel):
	oauth2_token: str

class DataJWT(BaseModel):
	jwt: str

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
	await sendRequest("post", "http://127.0.0.1:8013/auth-generator/logging", dataForLoggingUnsuccessfulRequest)

	return JSONResponse(
		status_code = 400,
		content = { "encryption": "failure", "error_message": "Input invalid." },
	)

@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "generation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/verify/api-key")
async def verificatorAPIKey(request: Request, data: DataAPIKey):
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	keyResult = await sendRequest(
		"get",
		"http://127.0.0.1:8012/auth-generator/data-info",
		{
			"auth_type": "api_key",
			"token_key": data.api_key
		}
	)
	if keyResult[0].get("getting_info") != "success":
		raise HTTPException(500)

	verificationResult = verifyAPIKey(keyResult[0].get("info"), currentTime)

	response = { "verification": "success", "is_valid": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": currentTime.isoformat(),
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

@app.get("/auth-generator/verify/oauth2")
async def verificatorOAuth2(request: Request, data: DataOAuth2Token):
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	tokenResult = await sendRequest(
		"get",
		"http://127.0.0.1:8012/auth-generator/data-info",
		{
			"auth_type": "oauth2_token",
			"token_key": data.oauth2_token,
			"user_id": 1
		}
	)
	if tokenResult[0].get("getting_info") != "success":
		raise HTTPException(500)

	verificationResult = verifyOAuth2(tokenResult[0].get("info"), currentTime, 1)
	print(verificationResult)

	response = { "verification": "success", "is_valid": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": currentTime.isoformat(),
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

@app.get("/auth-generator/verify/jwt")
async def verificatorJWT(request: Request, data: DataJWT):
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	tokenResult = await sendRequest(
		"get",
		"http://127.0.0.1:8012/auth-generator/data-info",
		{
			"auth_type": "jwt",
			"token_key": data.jwt,
			"user_id": 1
		}
	)
	if tokenResult[0].get("getting_info") != "success":
		raise HTTPException(500)
	
	verificationResult = verifyJWT(data.jwt, tokenResult[0].get("info"), currentTime, 1)
	print(verificationResult)
	
	response = { "verification": "success", "is_valid": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": currentTime.isoformat(),
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
