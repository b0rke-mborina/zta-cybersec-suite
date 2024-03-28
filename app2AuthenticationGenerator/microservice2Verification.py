from fastapi import FastAPI
from pydantic import BaseModel
from .utilityFunctions import verifyAPIKey, verifyOAuth2, verifyJWT


app = FastAPI()


class DataKey(BaseModel):
	key: str

class DataToken(BaseModel):
	token: str

@app.get("/auth-generator/verify/api-key")
async def verificatorAPIKey(data: DataKey):
	verificationResult = "valid" if verifyAPIKey() else "invalid"
	print(verificationResult)
	return { "generation": "success", "result": verificationResult }

@app.get("/auth-generator/verify/oauth2")
async def verificatorOAuth2(data: DataToken):
	verificationResult = "valid" if verifyOAuth2() else "invalid"
	print(verificationResult)
	return { "generation": "success", "result": verificationResult }

@app.get("/auth-generator/verify/jwt")
async def verificatorJWT(data: DataToken):
	verificationResult = "valid" if verifyJWT() else "invalid"
	print(verificationResult)
	return { "generation": "success", "result": verificationResult }
