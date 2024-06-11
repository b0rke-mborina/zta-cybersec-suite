import aiohttp
import asyncio
import hashlib
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
		authData["password_hash"] = hashData(password, "SHA-512")
	
	return authData

def hashData(data, algorithm):
	match algorithm:
		case "MD5":
			return hashlib.md5(data.encode()).hexdigest()
		case "SHA-1":
			return hashlib.sha1(data.encode()).hexdigest()
		case "SHA-256":
			return hashlib.sha256(data.encode()).hexdigest()
		case "SHA-512":
			return hashlib.sha512(data.encode()).hexdigest()

def verifyChecksum(data, algorithm, checksum):
	match algorithm:
		case "MD5":
			return hashlib.md5(data.encode()).hexdigest() == checksum
		case "SHA-1":
			return hashlib.sha1(data.encode()).hexdigest() == checksum
		case "SHA-256":
			return hashlib.sha256(data.encode()).hexdigest() == checksum
		case "SHA-512":
			return hashlib.sha512(data.encode()).hexdigest() == checksum
