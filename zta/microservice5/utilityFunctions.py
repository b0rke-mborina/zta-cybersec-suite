import aiohttp
import asyncio
import html
import re

async def request(session, method, url, data):
	async with session.request(method = method, url = url, json = data) as response:
			return await response.json()

async def sendRequest(method, url, reqData):
	async with aiohttp.ClientSession() as session:
		task = request(session, method, url, reqData)
		result = await asyncio.gather(task)
		return result

def validateData(data):
	isJwtValid = isStringValid(data.auth_data.jwt, False, r'^[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+\.|[A-Za-z0-9_-]+)+[A-Za-z0-9_-]+$')
	isUsernameValid = isStringValid(data.auth_data.username, True, r'^[a-zA-Z0-9._-]{3,20}$')
	isPasswordHashValid = isStringValid(data.auth_data.password_hash, True, r'^[a-fA-F0-9]{128}$')
	
	if not isJwtValid or not isUsernameValid or not isPasswordHashValid:
		return False
	else:
		return True

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

def getDataForIAM(data):
	dataForIAM = {
		"jwt": data.get("auth_data").get("jwt")
	}

	username = data.get("auth_data").get("username")
	passwordHash = data.get("auth_data").get("password_hash")
	if username != "":
		dataForIAM["username"] = username
	if passwordHash != "":
		dataForIAM["password_hash"] = passwordHash
	
	return dataForIAM

def getAppIdFromServiceAuthSource(serviceId):
	appId = 0
	if serviceId > 10 and serviceId < 20:
		appId = 1
	elif serviceId > 20 and serviceId < 30:
		appId = 2
	elif serviceId > 30 and serviceId < 40:
		appId = 3
	elif serviceId > 40 and serviceId < 50:
		appId = 4
	elif serviceId > 50 and serviceId < 60:
		appId = 5
	elif serviceId > 60 and serviceId < 70:
		appId = 6
	elif serviceId > 70 and serviceId < 80:
		appId = 7
	elif serviceId > 80 and serviceId < 90:
		appId = 8
	else:
		appId = 9
	return appId
