import base64
import datetime
import aiohttp
import asyncio
import aiosqlite
import json
import os.path
from Crypto.Cipher import Blowfish
from struct import pack

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

def handleProblem(problem):
	match problem:
		case "security_breach":
			handleSecurityBreach()
		case "dos_attack":
			handleDosAttack()
		case "data_inconsistency":
			handleDataInconsistency()
		case "data_compromise":
			handleDataCompromise()
		case "infrastructure_integrity_violation":
			handleInfrastructureIntegrityViolation()
		case "partial_system_failure":
			handlePartialSystemFailure()
		case "total_system_failure":
			handleTotalSystemFailure()

def handleSecurityBreach():
	pass

def handleDosAttack():
	pass

def handleDataInconsistency():
	pass

def handleDataCompromise():
	pass

def handleInfrastructureIntegrityViolation():
	pass

def handlePartialSystemFailure():
	pass

def handleTotalSystemFailure():
	pass

async def handleUserAuthentication(dbName, data):
	match data.auth_method.value:
		case "username_and_password":
			return authenticateUserWithUsernameAndPassword(dbName, data)
		case "jwt":
			return authenticateUserWithJwt(dbName, data)

async def authenticateUserWithUsernameAndPassword(dbName, data):
	result = (False, 0)
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM User WHERE username = ? AND password_hash = ?",
			(data.username, data.passwordHash)
		)
		dataFromDb = await cursor.fetchone()
		if len(dataFromDb) == 1:
			result[0] = True
			result[1] = dataFromDb[1]
	return result

async def authenticateUserWithJwt(dbName, data):
	result = (False, 0)
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM User WHERE jwt = ?",
			(data.jwt, )
		)
		dataFromDb = await cursor.fetchone()
		if len(dataFromDb) == 1:
			result[0] = True
			result[1] = dataFromDb[1]
	return result

async def checkUserNetworkSegment(dbName, data):
	result = False
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM Network WHERE user_id = ?",
			(data.user_id, )
		)
		dataFromDb = await cursor.fetchone()

		currentDatetime = datetime.datetime.now(datetime.timezone.utc)
		lastAuthenticated = datetime.datetime.fromisoformat(dataFromDb[0][3]).replace(tzinfo=datetime.timezone.utc)
		lastAuthenticationExpires = lastAuthenticated + datetime.timedelta(hours=1)
		if (data.auth_source_app_id == dataFromDb[0][2] and currentDatetime < lastAuthenticationExpires) or data.is_user_authenticated:
			result = True

	if data.is_user_authenticated:
		await updateUserNetworkSegment(dbName, data, currentDatetime)
	
	return result

async def updateUserNetworkSegment(dbName, data, currentDatetime):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE Network (current_app_id, last_authenticated) VALUES (?, ?) WHERE user_id = ?",
			(
				data.auth_source_app_id,
				currentDatetime.isoformat(),
				data.user_id
			)
		)
		await db.commit()

async def getAuthData(headers):
	result = (None, {})
	jwt = headers.get("jwt")
	username = headers.get("username")
	password = headers.get("password")
	if jwt is not None:
		result[0] = "jwt"
		result[1]["jwt"] = jwt
	elif username is not None and password is not None:
		result[0] = "username_and_password"
		result[1]["username"] = username
		result[1]["password"] = password
	return result

async def handleAuthorization():
	pass

async def checkIfPossibleDosAtack():
	pass

def encryptData(data):
	result = {}
	for key, value in data.items():
		(result[key], _, _) = encryptBlowfish(value)
	return result

def encryptBlowfish(plaintext):
	plaintext, key = plaintext.encode("utf-8"), "KEY_PLACEHOLDER".encode("utf-8")
	bs = Blowfish.block_size
	cipher = Blowfish.new(key, Blowfish.MODE_CBC)
	plen = bs - len(plaintext) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(plaintext + padding)
	print(key)
	return (base64.b64encode(ciphertext).decode("utf-8"), None, None)

def decryptData(data):
	result = {}
	for key, value in data.items():
		(result[key], _, _) = decryptBlowfish(value)
	return result

def decryptBlowfish(ciphertext):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = "KEY_PLACEHOLDER".encode("utf-8")
		iv = ciphertext[:Blowfish.block_size]
		cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
		padding_length = plaintext[-1]
		plaintext = plaintext[:-padding_length]
		return plaintext.decode()
	except:
		return ""

async def reportToAdmin():
	pass
