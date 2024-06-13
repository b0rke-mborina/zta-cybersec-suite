import aiohttp
import asyncio
import aiosqlite
import html
import re
import os.path
from fastapi.exceptions import RequestValidationError

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
		raise RequestValidationError("Filename must be unique.")

async def getFile(dbName, userId, filename):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM File WHERE user_id = ? AND filename = ?",
			(userId, filename)
		)
		result = await cursor.fetchall()
		print(result)
		return result
