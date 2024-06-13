import aiohttp
import asyncio
import datetime
import hashlib
from fastapi.exceptions import RequestValidationError

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

def validateThreatRequest(timeFrom, timeTo):
	datetimeFrom = datetime.datetime.fromisoformat(timeFrom).replace(tzinfo=datetime.timezone.utc)
	datetimeTo = datetime.datetime.fromisoformat(timeTo).replace(tzinfo=datetime.timezone.utc)
	if not datetimeFrom < datetimeTo:
		raise RequestValidationError("Request not valid.")
