import aiohttp
import asyncio
import aiosqlite
import jwt
import json
import datetime
import secrets
import string
import os.path

async def request(session, method, url, data):
	async with session.request(method = method, url = url, data = json.dumps(data)) as response:
			return await response.json()

async def sendRequest(method, url, reqData):
	async with aiohttp.ClientSession() as session:
		task = request(session, method, url, reqData)
		result = await asyncio.gather(task)
		return result

async def log(dataItem, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Log (timestamp, level, logger_source, user_id, request, response, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)",
			(
				dataItem.timestamp,
				dataItem.level,
				dataItem.logger_source,
				dataItem.user_id,
				dataItem.request,
				dataItem.response,
				dataItem.error_message
			)
		)
		await db.commit()

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def getData(authType, value, userId = None):
	print(authType, value, userId)
	match authType:
		case "api_key":
			return await getAPIKeyInfo("app2Data.db", value)
		case "oauth2_token":
			return await getOAuth2TokenInfo("app2Data.db", value, userId)
		case "jwt":
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
		case "api_key":
			return await storeAPIKey("app2Data.db", value, expires)
		case "oauth2_token":
			return await storeOAuth2Token("app2Data.db", value, expires, userId)
		case "jwt":
			return await storeJWT("app2Data.db", value, expires, userId, secret)

async def storeAPIKey(dbName, key, expires):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO APIKey (key, expires) VALUES (?, ?)",
			(key, expires)
		)
		await db.commit()

async def storeOAuth2Token(dbName, token, expires, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO OAuth2Token (token, expires, user_id) VALUES (?, ?, ?)",
			(token, expires, userId)
		)
		await db.commit()

async def storeJWT(dbName, token, expires, userId, secret):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO JWT (token, expires, user_id, secret) VALUES (?, ?, ?, ?)",
			(token, expires, userId, secret)
		)
		await db.commit()

def generateAPIKey():
	alphabet = string.ascii_letters + string.digits
	return ''.join(secrets.choice(alphabet) for _ in range(32))

def generateOAuth2():
	return secrets.token_urlsafe(32)

def generateJWT():
	payload = { "data": { "user_id": 1, "expires": "2024-07-07" } }
	secretKey = "SECRET_KEY_PLACEHOLDER"
	expiration_time_hours = 24
	expiration_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=expiration_time_hours)
	token = jwt.encode({'data': payload, 'exp': expiration_time}, secretKey, algorithm='HS256')
	return token

async def verifyAPIKey(dataFromDb, currentDatetime):
	if len(dataFromDb) == 0:
		return False
	
	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][1]).replace(tzinfo=datetime.timezone.utc)
	return datetimeFromDb > currentDatetime

def verifyOAuth2():
	return True

def verifyJWT():
	return True
