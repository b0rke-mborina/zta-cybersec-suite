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

def checkData(data):
	if not isinstance(data, list):
		raise RequestValidationError("Data is not a list.")
    
	if not all(isinstance(sublist, list) for sublist in data):
		raise RequestValidationError("Data is not a list of lists.")
	
	if len(set(len(sublist) for sublist in data)) != 1:
		raise RequestValidationError("Lists inside the provided data list are not of equal length.")
	
	for sublist in data:
		if not all(isinstance(item, (str, int, float, bool, type(None))) for item in sublist):
			raise RequestValidationError("Lists inside the provided data list don't include only basic types.")
