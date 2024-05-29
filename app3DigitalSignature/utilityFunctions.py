import aiohttp
import asyncio
import aiosqlite
import hashlib
import html
import re
import base64
import os.path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

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

async def checkIfUserAllowed(dbName, userId, role):
	tasks = [isRoleAllowed(dbName, role), isUserAllowed(dbName, userId)]
	results = await asyncio.gather(*tasks)
	return results[0] and results[1]

async def isRoleAllowed(dbName, role):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM ACL WHERE role = ?",
			(role, )
		)
		result = await cursor.fetchone()
		return result[2] == "eMviHPAW92g=" # == 1

async def isUserAllowed(dbName, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM ACL WHERE user_id = ?",
			(userId, )
		)
		result = await cursor.fetchone()
		return result[2] == "eMviHPAW92g=" # == 1

def verifySignature(publicKeyBase64, signatureBase64, message, hashType):
	try:
		(publicKeyBytes, signatureBytes, messageBytes, hasher) = handleParams(publicKeyBase64, signatureBase64, message, hashType)

		publicKey = serialization.load_pem_public_key(publicKeyBytes, backend=default_backend())

		publicKey.verify(
			signatureBytes,
			messageBytes,
			padding.PKCS1v15(),
			hasher
		)
		return True
	except Exception as e:
		print("Error:", e)
		return False

def handleParams(publicKeyBase64, signatureBase64, message, hashType):
	try:
		publicKeyBytes = base64.b64decode(publicKeyBase64)
		signatureBytes = base64.b64decode(signatureBase64)
		messageBytes = message.encode("utf-8")
		hasher = hashes.SHA256() if hashType == 'sha256' else hashes.SHA512()
		return (publicKeyBytes, signatureBytes, messageBytes, hasher)
	except:
		return (None, None, None, None)
