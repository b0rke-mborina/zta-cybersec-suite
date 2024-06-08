import aiohttp
import asyncio
import aiosqlite
import html
import re
import os.path

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

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def handleUserAuthentication(dbName, data):
	tasks = [
		authenticateUserWithJwt(dbName, data),
		authenticateUserWithUsernameAndPassword(dbName, data)
	]
	results = await asyncio.gather(*tasks)
	return (results[0][0], results[1][0], results[0][1], results[0][2])

async def authenticateUserWithUsernameAndPassword(dbName, data):
	isAuthenticated, userId, userRole = False, "35oIObfdlDo=", "3DoxBhFdBD8=" # False, 0, "user"
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM User WHERE username = ? AND password_hash = ?",
			(data["username"], data["password_hash"])
		)
		dataFromDb = await cursor.fetchone()
		if dataFromDb is not None:
			isAuthenticated = True
			userId = dataFromDb[0]
			if dataFromDb[1] != "3DoxBhFdBD8=":
				userRole = dataFromDb[1]
	return (isAuthenticated, userId, userRole)

async def authenticateUserWithJwt(dbName, data):
	isAuthenticated, userId, userRole = False, "35oIObfdlDo=", "3DoxBhFdBD8=" # False, 0, "user"
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM User WHERE jwt = ?",
			(data["jwt"], )
		)
		dataFromDb = await cursor.fetchone()
		if dataFromDb is not None:
			isAuthenticated = True
			userId = dataFromDb[0]
			if dataFromDb[1] != "3DoxBhFdBD8=":
				userRole = dataFromDb[1]
	return (isAuthenticated, userId, userRole)
