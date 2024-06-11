import aiohttp
import asyncio
import jwt
import datetime
import hashlib
import html
import re
import base64

async def request(session, method, url, data):
	async with session.request(method = method, url = url, json = data) as response:
			return await response.json()

async def sendRequest(method, url, reqData):
	async with aiohttp.ClientSession() as session:
		task = request(session, method, url, reqData)
		result = await asyncio.gather(task)
		return result

def isStringValid(strValue, allowNoneOrEmpty, regex):
	if not allowNoneOrEmpty and (strValue is None or strValue.strip() == ""):
		return False
	
	sanitizedStrValue = html.escape(strValue)
	if strValue != sanitizedStrValue:
		return False
	
	pattern = re.compile(regex)
	if not pattern.match(strValue):
		return False
	
	return True

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

def verifyAPIKey(dataFromDb, currentDatetime):
	if len(dataFromDb) == 0:
		return False
	
	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][1]).replace(tzinfo=datetime.timezone.utc)
	return datetimeFromDb > currentDatetime

def verifyOAuth2(dataFromDb, currentDatetime, userId):
	if len(dataFromDb) == 0:
		return False

	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][2]).replace(tzinfo=datetime.timezone.utc)
	userIdFromDb = dataFromDb[0][0]

	return datetimeFromDb > currentDatetime and userId == userIdFromDb

def verifyJWT(token, dataFromDb, currentDatetime, userId):
	if len(dataFromDb) == 0:
		return False

	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][3]).replace(tzinfo=datetime.timezone.utc)
	userIdFromDb = dataFromDb[0][0]
	# secretFromDb = dataFromDb[0][2]
	
	try:
		decodedPayload = jwt.decode(token, "SECRET_KEY_PLACEHOLDER", algorithms=['HS256']) # base64.b64decode(secretFromDb) # PLACEHOLDER
		print(decodedPayload)

		datetimeFromPayload = datetime.datetime.fromisoformat(decodedPayload.get("expires")).replace(tzinfo=datetime.timezone.utc)
		userIdFromPayload = decodedPayload.get("user_id")

		isDatetimeOk = datetimeFromDb == datetimeFromPayload and datetimeFromPayload > currentDatetime
		isUserIdOk = userIdFromDb == userIdFromPayload and userIdFromPayload == userId

		return isDatetimeOk and isUserIdOk
	except:
		return False
