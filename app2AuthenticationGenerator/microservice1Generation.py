from fastapi import FastAPI
from .utilityFunctions import generateAPIKey, generateOAuth2, generateJWT


app = FastAPI()


@app.get("/auth-generator/generate/api-key")
async def generatorAPIKey():
	apiKey = generateAPIKey()
	print(apiKey)
	return { "generation": "success", "api_key": apiKey }

@app.get("/auth-generator/generate/oauth2")
async def generatorOAuth2():
	oauth2Token = generateOAuth2()
	print(oauth2Token)
	return { "generation": "success", "oauth2_token": oauth2Token }

@app.get("/auth-generator/generate/jwt")
async def generatorJWT():
	jwtToken = generateJWT()
	print(jwtToken)
	return { "generation": "success", "jwt_token": jwtToken }
