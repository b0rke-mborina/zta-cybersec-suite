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

async def getData(authType, value, userId = None):
	print(authType, value, userId)
	match authType:
		case "tEq0nzMfSsQ=": # api_key
			return await getAPIKeyInfo("app2Data.db", value)
		case "S52Z0ZDeDS7mKe43X+Y2sg==": # oauth2_token
			return await getOAuth2TokenInfo("app2Data.db", value, userId)
		case "MKgIfWpSwwI=": # jwt
			return await getJWTInfo("app2Data.db", value, userId)

async def getAPIKeyInfo(dbName, key):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM APIKey WHERE key = ?",
			(key, )
		)
		result = await cursor.fetchall()
		print(result)
		return result

async def getOAuth2TokenInfo(dbName, token, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM OAuth2Token WHERE token = ? AND user_id = ?",
			(token, userId)
		)
		result = await cursor.fetchall()
		print(result)
		return result

async def getJWTInfo(dbName, token, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM JWT WHERE token = ? AND user_id = ?",
			(token, userId)
		)
		result = await cursor.fetchall()
		print(result)
		return result

async def saveData(authType, value, expires, userId = None, secret = None):
	print(authType, value, expires, userId, secret)
	match authType:
		case "tEq0nzMfSsQ=": # api_key
			return await storeAPIKey("app2Data.db", value, expires)
		case "S52Z0ZDeDS7mKe43X+Y2sg==": # oauth2_token
			return await storeOAuth2Token("app2Data.db", userId, value, expires)
		case "MKgIfWpSwwI=": # jwt
			return await storeJWT("app2Data.db", userId, value, secret, expires)

async def storeAPIKey(dbName, key, expires):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO APIKey (key, expires) VALUES (?, ?)",
			(key, expires)
		)
		await db.commit()

async def storeOAuth2Token(dbName, userId, token, expires):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO OAuth2Token (user_id, token, expires) VALUES (?, ?, ?)",
			(userId, token, expires)
		)
		await db.commit()

async def storeJWT(dbName, userId, token, secret, expires):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO JWT (user_id, token, secret, expires) VALUES (?, ?, ?, ?)",
			(userId, token, secret, expires)
		)
		await db.commit()
