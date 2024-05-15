from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import datetime
from .utilityFunctions import sendRequest, generateAPIKey, generateOAuth2, generateJWT


app = FastAPI()


@app.exception_handler(HTTPException)
async def httpExceptionHandler(request, exc):
	return JSONResponse(
		status_code = 500,
		content = { "generation": "failure", "error_message": "Unexpected error occured." },
	)

@app.get("/auth-generator/generate/api-key")
async def generatorAPIKey():
	apiKey = generateAPIKey()
	print(apiKey)
	currentTime = datetime.datetime.now()
	apiKeyData = {
		"auth_type": "api_key",
		"token_key": apiKey,
		"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
	}

	response = { "generation": "success", "api_key": apiKey }

	storageResult = await sendRequest(
		"post",
		"http://127.0.0.1:8012/auth-generator/data-new",
		apiKeyData
	)
	if storageResult[0].get("saving_info") != "success":
		raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": currentTime.isoformat(),
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

@app.get("/auth-generator/generate/oauth2")
async def generatorOAuth2():
	oauth2Token = generateOAuth2()
	print(oauth2Token)
	currentTime = datetime.datetime.now()
	oauth2TokenData = {
		"auth_type": "oauth2_token",
		"token_key": oauth2Token,
		"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
		"user_id": 1
	}

	response = { "generation": "success", "oauth2_token": oauth2Token }

	storageResult = await sendRequest(
		"post",
		"http://127.0.0.1:8012/auth-generator/data-new",
		oauth2TokenData
	)
	if storageResult[0].get("saving_info") != "success":
		raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": currentTime.isoformat(),
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

@app.get("/auth-generator/generate/jwt")
async def generatorJWT():
	jwToken = generateJWT()
	print(jwToken)
	currentTime = datetime.datetime.now(datetime.timezone.utc)
	oauth2TokenData = {
		"auth_type": "jwt",
		"token_key": jwToken,
		"expires": (currentTime + datetime.timedelta(days=14)).isoformat(),
		"user_id": 1,
		"secret": "SECRET_KEY_PLACEHOLDER"
	}

	response = { "generation": "success", "oauth2_token": jwToken }

	storageResult = await sendRequest(
		"post",
		"http://127.0.0.1:8012/auth-generator/data-new",
		oauth2TokenData
	)
	if storageResult[0].get("saving_info") != "success":
		raise HTTPException(500)

	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": currentTime.isoformat(),
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
	
	return { "generation": "success", "jwtoken": jwToken }
