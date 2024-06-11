import aiohttp
import asyncio
import aiosqlite
import html
import re
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

async def storeReport(dataItem, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Report (timestamp, logger_source, user_id, data, checksum, error_message) VALUES (?, ?, ?, ?, ?, ?)",
			(
				dataItem["timestamp"],
				dataItem["logger_source"],
				dataItem["user_id"],
				dataItem["data"],
				dataItem["checksum"],
				f"Data integrity issue. {dataItem['error_message']}"
			)
		)
		await db.commit()

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath
