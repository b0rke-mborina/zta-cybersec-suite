import aiohttp
import asyncio
import aiosqlite
import json
import base64
import os.path
from Crypto.Cipher import AES
from fastapi.exceptions import RequestValidationError

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
		return result[2] == 1

async def isUserAllowed(dbName, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM ACL WHERE user_id = ?",
			(userId, )
		)
		result = await cursor.fetchone()
		return result[2] == 1

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def storeFile(dbName, userId, filename, format, file, key, tag, nonce):
	try:
		async with aiosqlite.connect(getDbPath(dbName)) as db:
			await db.execute(
				"INSERT INTO File (user_id, filename, format, file, key, tag, nonce) VALUES (?, ?, ?, ?, ?, ?, ?)",
				(
					userId,
					filename,
					format,
					file,
					key,
					tag,
					nonce
				)
			)
			await db.commit()
	except:
		raise RequestValidationError("Username must be unique.")

async def getFile(dbName, userId, filename):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM File WHERE user_id = ? AND filename = ?",
			(userId, filename)
		)
		result = await cursor.fetchall()
		print(result)
		return result

async def encryptFile(file):
	key = "key_placeholder1" # must be 16 chars
	cipher = AES.new(key.encode("utf-8"), AES.MODE_EAX)
	ciphertext, tag = cipher.encrypt_and_digest(file.encode("utf-8"))
	return (
		base64.b64encode(ciphertext).decode("utf-8"),
		key,
		base64.b64encode(tag).decode("utf-8"),
		base64.b64encode(cipher.nonce).decode("utf-8")
	)

async def decryptFile(file, key, tag, nonce):
	file = base64.b64decode(file)
	key = key.encode("utf-8")
	tag = base64.b64decode(tag)
	nonce = base64.b64decode(nonce)
	cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
	plaintext = cipher.decrypt_and_verify(file, tag)
	return plaintext.decode()
