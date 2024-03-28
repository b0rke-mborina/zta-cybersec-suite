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

def verifyAPIKey():
	return True

def verifyOAuth2():
	return True

def verifyJWT():
	return True

async def getData():
	return {}

async def saveData():
	pass
