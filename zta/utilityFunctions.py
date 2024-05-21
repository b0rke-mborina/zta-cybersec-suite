import aiohttp
import asyncio
import aiosqlite
import datetime
import hashlib
import base64
import os.path
from Crypto.Cipher import Blowfish
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
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 1, # PLACEHOLDER
				"user_id": 1, # PLACEHOLDER
				"request": f"Request: {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}",
				"response": str(response),
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
		case "authorize":
			if data.user_id == 0:
				return [False, False]
			else:
				tasks = [
					handleAuthorization(dbName, data.user_id, data.user_role),
					checkIfPossibleDosAtack("ztaACL.db", data.user_id, data.is_user_authenticated_additionally)
				]
				return await asyncio.gather(*tasks)
		case "deny_access_to_all":
			await denyAccessToAll(dbName)
			return ["", ""]
		case "deny_access_to_users":
			await denyAccessToUsers(dbName)
			return ["", ""]
		case "deny_access_to_user":
			await denyAccessToUser(dbName, data.user_id)
			return ["", ""]

async def denyAccessToAll(dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute("UPDATE ACL SET isAllowed = 0 WHERE role = 'user' OR role = 'admin'")
		await db.commit()

async def denyAccessToUsers(dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute("UPDATE ACL SET isAllowed = 0 WHERE role = 'user'")
		await db.commit()

async def denyAccessToUser(dbName, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE ACL SET isAllowed = 0 WHERE user_id = ?",
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
	isAuthenticated, userId, userRole = False, 0, "user"
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM User WHERE username = ? AND password_hash = ?",
			(data.username, data.password_hash)
		)
		dataFromDb = await cursor.fetchone()
		if dataFromDb is not None:
			isAuthenticated = True
			userId = dataFromDb[0]
			if dataFromDb[1] != "user":
				userRole = dataFromDb[1]
	return (isAuthenticated, userId, userRole)

async def authenticateUserWithJwt(dbName, data):
	isAuthenticated, userId, userRole = False, 0, "user"
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM User WHERE jwt = ?",
			(data.jwt, )
		)
		dataFromDb = await cursor.fetchone()
		if dataFromDb is not None:
			isAuthenticated = True
			userId = dataFromDb[0]
			if dataFromDb[1] != "user":
				userRole = dataFromDb[1]
	return (isAuthenticated, userId, userRole)

async def checkUserNetworkSegment(dbName, data):
	result = False
	if data.user_id == 0:
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
		if (data.auth_source_app_id == dataFromDb[1] and currentDatetime < lastAuthenticationExpires) or data.is_user_authenticated_additionally:
			result = True

	if data.is_user_authenticated_additionally:
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
		"auth_source": data.auth_source,
		"jwt": data.auth_data.get("jwt")
	}

	if data.auth_data.get("username") is not None:
		dataForIAM["username"] = data.auth_data.get("username")
	if data.auth_data.get("password_hash") is not None:
		dataForIAM["password_hash"] = data.auth_data.get("password_hash")
	
	return dataForIAM

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
		return result[2] == 1

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
			return result[2] == 1

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
	for key, value in data.items():
		(result[key], _, _) = encryptBlowfish(value)
	return result

def encryptBlowfish(plaintext):
	if isinstance(plaintext, int):
		plaintext = intToBytes(plaintext)
	else:
		plaintext = plaintext.encode("utf-8")
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
	bs = Blowfish.block_size
	cipher = Blowfish.new(key, Blowfish.MODE_CBC)
	plen = bs - len(plaintext) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(plaintext + padding)
	return (base64.b64encode(ciphertext).decode("utf-8"), None, None)

def decryptData(data):
	result = {}
	for key, value in data.items():
		(result[key], _, _) = decryptBlowfish(value)
	return result

def decryptBlowfish(ciphertext):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
		iv = ciphertext[:Blowfish.block_size]
		cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
		padding_length = plaintext[-1]
		plaintext = plaintext[:-padding_length]
		return plaintext.decode()
	except:
		return ""

def intToBytes(intData):
	return intData.to_bytes((intData.bit_length() + 7) // 8, byteorder='big')

def bytesToInt(byteData):
	return int.from_bytes(byteData, byteorder='big')

def hashData(data):
	return hashlib.sha512(data.encode()).hexdigest()
