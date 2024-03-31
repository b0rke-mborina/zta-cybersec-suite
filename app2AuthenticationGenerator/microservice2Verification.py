from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .utilityFunctions import sendRequest, verifyAPIKey, verifyOAuth2, verifyJWT
import datetime


app = FastAPI()


class DataAPIKey(BaseModel):
	api_key: str

class DataOAuth2Token(BaseModel):
	oauth2_token: str

class DataJWT(BaseModel):
	jwt: str

@app.get("/auth-generator/verify/api-key")
async def verificatorAPIKey(data: DataAPIKey):
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

	verificationResult = "valid" if await verifyAPIKey(keyResult[0].get("info")) else "invalid"

	response = { "verification": "success", "result": verificationResult }
	
	loggingResult = await sendRequest(
		"post",
		"http://127.0.0.1:8013/auth-generator/logging",
		{
			"timestamp": datetime.datetime.now().isoformat(),
			"level": "INFO",
			"logger_source": 1,
			"user_id": 1,
			"request": str(data),
			"response": str(response),
			"error_message": ""
		}
	)
	if loggingResult[0].get("logging") != "success":
		raise HTTPException(500)
	
	return response

@app.get("/auth-generator/verify/oauth2")
async def verificatorOAuth2(data: DataOAuth2Token):
	verificationResult = "valid" if verifyOAuth2() else "invalid"
	print(verificationResult)
	return { "generation": "success", "result": verificationResult }

@app.get("/auth-generator/verify/jwt")
async def verificatorJWT(data: DataJWT):
	verificationResult = "valid" if verifyJWT() else "invalid"
	print(verificationResult)
	return { "generation": "success", "result": verificationResult }
