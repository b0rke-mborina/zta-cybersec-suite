import aiohttp
import asyncio
import aiosqlite
import json
import os.path

async def request(session, method, url, data):
	async with session.request(method = method, url = url, data = json.dumps(data)) as response:
			return await response.json()

async def task(method, url, reqData):
	async with aiohttp.ClientSession() as session:
		task = request(session, method, url, reqData)
		result = await asyncio.gather(task)
		return result

async def log(dataItem, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Log (timestamp, level, logger_source, user_id, request, error_message) VALUES (?, ?, ?, ?, ?, ?)",
			(
				dataItem.timestamp,
				dataItem.level,
				dataItem.logger_source,
				dataItem.user_id,
				dataItem.request,
				dataItem.error_message
			)
		)
		await db.commit()

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def getKey(userId, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		cursor = await db.cursor()
		await cursor.execute("SELECT * FROM Key WHERE user_id = ?", (userId, ))
		results = await cursor.fetchall()
		print("numberOfKeys", len(results))

async def storeKey(userId, key, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Key (user_id, key) VALUES (?, ?)",
			(userId, key)
		)
		await db.commit()
