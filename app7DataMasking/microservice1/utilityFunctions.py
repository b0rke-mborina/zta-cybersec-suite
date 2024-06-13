import aiohttp
import asyncio
import copy
import hashlib
import html
import re
from faker import Faker
from fastapi.exceptions import RequestValidationError

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

def checkData(data):
	if not isinstance(data, list):
		raise RequestValidationError("Data is not a list.")
    
	if not all(isinstance(sublist, list) for sublist in data):
		raise RequestValidationError("Data is not a list of lists.")
	
	if len(set(len(sublist) for sublist in data)) != 1:
		raise RequestValidationError("Lists inside the provided data list are not of equal length.")
	
	for sublist in data:
		if not all(isinstance(item, (str, int, float, bool, type(None))) for item in sublist):
			raise RequestValidationError("Lists inside the provided data list don't include only basic types.")

def maskData(data):
	print(data)
	fake = Faker()
	maskedData = copy.deepcopy(data)
	for i in range(len(maskedData)):
		for j in range(len(maskedData[i])):
			if maskedData[i][j] is None:
				maskedData[i][j] = "MASKED"
			elif isinstance(maskedData[i][j], bool):
				maskedData[i][j] = fake.boolean()
			elif isinstance(maskedData[i][j], int):
				maskedData[i][j] = fake.random_int()
			elif isinstance(maskedData[i][j], float):
				maskedData[i][j] = fake.random_number()
			elif isinstance(maskedData[i][j], str):
				maskedData[i][j] = fake.word()
			else:
				maskedData[i][j] = "MASKED"
	return maskedData
