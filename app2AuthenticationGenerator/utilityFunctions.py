import aiohttp
import asyncio
import aiosqlite
import jwt
import datetime
import hashlib
import secrets
import string
import html
import re
import base64
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

async def log(dataItem, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Log (timestamp, level, logger_source, user_id, request, response, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)",
			(
				dataItem["timestamp"],
				dataItem["level"],
				dataItem["logger_source"],
				dataItem["user_id"],
				dataItem["request"],
				dataItem["response"],
				dataItem["error_message"]
			)
		)
		await db.commit()

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

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
			return await storeOAuth2Token("app2Data.db", userId, value, expires)
		case "jwt":
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

def generateAPIKey():
	alphabet = string.ascii_letters + string.digits
	return ''.join(secrets.choice(alphabet) for _ in range(32))

def generateOAuth2():
	return secrets.token_urlsafe(32)

def generateJWT(userId):
	secretKey = "SECRET_KEY_PLACEHOLDER" # PLACEHOLDER
	expiration_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)).isoformat()
	token = jwt.encode({ "user_id": userId, "expires": expiration_time }, secretKey, algorithm='HS256')
	return token

def verifyAPIKey(dataFromDb, currentDatetime):
	if len(dataFromDb) == 0:
		return False
	
	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][1]).replace(tzinfo=datetime.timezone.utc)
	return datetimeFromDb > currentDatetime

def verifyOAuth2(dataFromDb, currentDatetime, userId):
	if len(dataFromDb) == 0:
		return False

	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][1]).replace(tzinfo=datetime.timezone.utc)
	userIdFromDb = dataFromDb[0][2]

	return datetimeFromDb > currentDatetime and userId == userIdFromDb

def verifyJWT(token, dataFromDb, currentDatetime, userId):
	if len(dataFromDb) == 0:
		return False

	datetimeFromDb = datetime.datetime.fromisoformat(dataFromDb[0][1]).replace(tzinfo=datetime.timezone.utc)
	userIdFromDb = dataFromDb[0][2]
	# secretFromDb = dataFromDb[0][3]
	
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
