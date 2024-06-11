import aiohttp
import asyncio
import jwt
import datetime
import hashlib
import secrets
import string

async def request(session, method, url, data):
	async with session.request(method = method, url = url, json = data) as response:
			return await response.json()

async def sendRequest(method, url, reqData):
	async with aiohttp.ClientSession() as session:
		task = request(session, method, url, reqData)
		result = await asyncio.gather(task)
		return result

def getAuthData(headers):
	jwt = headers.get("jwt")
	username = headers.get("username")
	password = headers.get("password")

	authData = {
		"jwt": jwt if jwt is not None and jwt != "" else ""
	}
	if username is not None and username != "" and password is not None and password != "":
		authData["username"] = username
		authData["password_hash"] = hashData(password)
	
	return authData

def hashData(data):
	return hashlib.sha512(data.encode()).hexdigest()

def generateAPIKey():
	alphabet = string.ascii_letters + string.digits
	return ''.join(secrets.choice(alphabet) for _ in range(32))

def generateOAuth2():
	return secrets.token_urlsafe(32)

def generateJWT(userId):
	secretKey = "SECRET_KEY_PLACEHOLDER" # PLACEHOLDER
	expirationDatetime = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)).isoformat()
	token = jwt.encode({ "user_id": userId, "expires": expirationDatetime }, secretKey, algorithm='HS256')
	return token
