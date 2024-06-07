import aiohttp
import asyncio
import aiosqlite
import datetime
import hashlib
import html
import re
import base64
import os.path
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from struct import pack
import pika

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

async def handleProblem(request, data, response):
	tasks = [
		reportToAdmin(data.problem),
		sendRequest(
			"post",
			"http://127.0.0.1:8087/zta/monitoring",
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),# .translate(str.maketrans("\"'{}:", "_____")),
				"level": "INFO",
				"logger_source": 1,
				"user_id": data.user_id,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": data.problem
			}
		)
	]
	
	if data.problem in ["security_breach", "infrastructure_integrity_violation"]:
		tasks.append(
			sendRequest(
				"get",
				"http://127.0.0.1:8083/zta/acl",
				{
					"task": "deny_access_to_all"
				}
			)
		)
	elif data.problem in ["data_inconsistency", "partial_system_failure", "total_system_failure"]:
		tasks.append(
			sendRequest(
				"get",
				"http://127.0.0.1:8083/zta/acl",
				{
					"task": "deny_access_to_users"
				}
			)
		)
	elif data.problem == "dos_attack":
		tasks.append(
			sendRequest(
				"get",
				"http://127.0.0.1:8083/zta/acl",
				{
					"task": "deny_access_to_user",
					"user_id": data.user_id
				}
			)
		)
	
	await asyncio.gather(*tasks)

async def reportToAdmin(problem):
	connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
	channel = connection.channel()

	channel.queue_declare(queue = "notifications")
	channel.basic_publish(
		exchange = "",
		routing_key = "notifications",
		body = problem
	)

	print("Notification sent")
	connection.close()

async def handleACLTask(dbName, data):
	match data.task:
		case "eZ9FPVVabeN6dDFRZ9itdA==":
			if data.user_id == "35oIObfdlDo=":
				return [False, False]
			else:
				tasks = [
					handleAuthorization(dbName, data.user_id, data.user_role),
					checkIfPossibleDosAtack("ztaACL.db", data.user_id, data.is_user_authenticated_additionally)
				]
				return await asyncio.gather(*tasks)
		case "r+KhlYVgRAQABXy35o6JOCACeHZG6q5o":
			await denyAccessToAll(dbName)
			return ["", ""]
		case "r+KhlYVgRAQI7B9eX5vQoBZazil7VuSO":
			await denyAccessToUsers(dbName)
			return ["", ""]
		case "r+KhlYVgRAQI7B9eX5vQoKm6HFXK1u4G":
			await denyAccessToUser(dbName, data.user_id)
			return ["", ""]

async def denyAccessToAll(dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute("UPDATE ACL SET is_allowed = '35oIObfdlDo=' WHERE role = '3DoxBhFdBD8=' OR role = '4I1FoHuYuxc='") # 'user' or 'admin'
		await db.commit()

async def denyAccessToUsers(dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute("UPDATE ACL SET is_allowed = '35oIObfdlDo=' WHERE role = '3DoxBhFdBD8='") # 'user'
		await db.commit()

async def denyAccessToUser(dbName, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE ACL SET is_allowed = '35oIObfdlDo=' WHERE user_id = ?",
			(userId, )
		)
		await db.commit()

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

async def checkUserNetworkSegment(dbName, data):
	result = False
	if data.user_id == "35oIObfdlDo=": # == 0
		return False
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM Network WHERE user_id = ?",
			(data.user_id, )
		)
		dataFromDb = await cursor.fetchone()

		currentDatetime = datetime.datetime.now(datetime.timezone.utc)
		lastAuthenticated = datetime.datetime.fromisoformat(dataFromDb[2]).replace(tzinfo=datetime.timezone.utc)
		lastAuthenticationExpires = lastAuthenticated + datetime.timedelta(hours=1)
		if (data.auth_source_app_id == dataFromDb[1] and currentDatetime < lastAuthenticationExpires) or data.is_user_authenticated_additionally == "eMviHPAW92g=": # == 1
			result = True

	if data.is_user_authenticated_additionally == "eMviHPAW92g=": # == 1
		await updateUserNetworkSegment(dbName, data, currentDatetime)
	
	return result

async def updateUserNetworkSegment(dbName, data, currentDatetime):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE Network SET current_app_id = ?, last_authenticated = ? WHERE user_id = ?",
			(
				data.auth_source_app_id,
				currentDatetime.isoformat(),
				data.user_id
			)
		)
		await db.commit()

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

async def handleAuthorization(dbName, userId, userRole):
	tasks = [isRoleAllowed(dbName, userRole), isUserAllowed(dbName, userId)]
	results = await asyncio.gather(*tasks)
	return results[0] and results[1]

async def isRoleAllowed(dbName, role):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM ACL WHERE role = ?",
			(role, )
		)
		result = await cursor.fetchone()
		return result[2] == "eMviHPAW92g=" # is_allowed == 1

async def isUserAllowed(dbName, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM ACL WHERE user_id = ?",
			(userId, )
		)
		result = await cursor.fetchone()
		if result is None:
			return False
		else:
			return result[2] == "eMviHPAW92g=" # is_allowed == 1

async def checkIfPossibleDosAtack(dbName, userId, isAuthenticated):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM ACL WHERE user_id = ?",
			(userId, )
		)
		result = await cursor.fetchone()
		if result is None:
			return False

		currentDatetime = datetime.datetime.now(datetime.timezone.utc)
		requestsStarted = datetime.datetime.fromisoformat(result[3]).replace(tzinfo=datetime.timezone.utc)
		requestsExpire = requestsStarted + datetime.timedelta(hours=1)

		isRequestsTimestampValid = requestsExpire > currentDatetime
		isNumberOfRequestsHigh = result[4] > 100

		if isAuthenticated:
			if isRequestsTimestampValid:
				await incrementRequestData(dbName, userId, result[4])
			else:
				await resetRequestData(dbName, userId, currentDatetime)
		
		return isRequestsTimestampValid and isNumberOfRequestsHigh

async def incrementRequestData(dbName, userId, requestCount):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE ACL SET request_count = ? WHERE user_id = ?",
			(
				requestCount + 1,
	 			userId
			)
		)
		await db.commit()

async def resetRequestData(dbName, userId, datetime):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE ACL SET request_timestamp = ?, request_count = 1 WHERE user_id = ?",
			(
				datetime.isoformat(),
	 			userId
			)
		)
		await db.commit()

def encryptData(data):
	result = {}
	for field, value in data.items():
		result[field] = encryptBlowfish(field, value)
	return result

def encryptBlowfish(field, plaintext):
	plaintextBytes = intToBytes(plaintext) if isIntValue(field) else plaintext.encode("utf-8")
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
	ciphertext = None

	if useDeterministicCryptography(field):
		mode = Blowfish.MODE_ECB
		cipher = Blowfish.new(key, Blowfish.MODE_ECB)
		paddedText = pad(plaintextBytes, Blowfish.block_size)
		ciphertext = cipher.encrypt(paddedText)
	else:
		mode = Blowfish.MODE_CBC
		cipher = Blowfish.new(key, mode)
		bs = Blowfish.block_size
		plen = bs - len(plaintextBytes) % bs
		padding = [plen]*plen
		padding = pack('b'*plen, *padding)
		ciphertext = cipher.iv + cipher.encrypt(plaintextBytes + padding)

	return base64.b64encode(ciphertext).decode("utf-8")

def decryptData(data):
	result = {}
	for field, value in data.items():
		result[field] = decryptBlowfish(field, value)
	return result

def decryptBlowfish(field, ciphertext):
	try:
		ciphertextBytes = base64.b64decode(ciphertext)
		key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
		plaintextBytes = None

		if useDeterministicCryptography(field):
			cipher = Blowfish.new(key, Blowfish.MODE_ECB)
			plaintextBytes = unpad(cipher.decrypt(ciphertextBytes), Blowfish.block_size)
		else:
			iv = ciphertextBytes[:Blowfish.block_size]
			cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
			plaintextBytes = cipher.decrypt(ciphertextBytes[Blowfish.block_size:])
			paddingLength = plaintextBytes[-1]
			plaintextBytes = plaintextBytes[:-paddingLength]

		plaintext = bytesToInt(plaintextBytes) if isIntValue(field) else plaintextBytes.decode("utf-8")
		return plaintext
	except:
		return ""

def intToBytes(intData):
	return intData.to_bytes((intData.bit_length() + 7) // 8, byteorder='big')

def bytesToInt(byteData):
	return int.from_bytes(byteData, byteorder='big')

def hashData(data):
	return hashlib.sha512(data.encode()).hexdigest()

def isIntValue(field):
	intFields = {
		"logger_source", "user_id", "is_allowed", "request_count",
		"current_app_id", "auth_source_app_id", "is_user_authenticated_additionally"
	}
	return field in intFields

def useDeterministicCryptography(field):
	deterministicFields = {
		"user_id", "role", "username", "key", "token", "filename", "dataset", "severity",
		"password_hash", "jwt", "auth_source_app_id", "is_user_authenticated_additionally", 
		"task", "auth_type", "token_key"
	}
	return field in deterministicFields
