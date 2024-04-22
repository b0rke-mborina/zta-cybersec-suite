import aiohttp
import asyncio
import aiosqlite
import json
import os.path
from fastapi.exceptions import RequestValidationError

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
		result = await cursor.fetchall()
		return len(result) == 0

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def storeFile(dbName, userId, filename, format, file):
	try:
		async with aiosqlite.connect(getDbPath(dbName)) as db:
			await db.execute(
				"INSERT INTO File (user_id, filename, format, file) VALUES (?, ?, ?, ?)",
				(
					userId,
					filename,
					format,
					file
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
	pass

async def decryptFile(file):
	pass
