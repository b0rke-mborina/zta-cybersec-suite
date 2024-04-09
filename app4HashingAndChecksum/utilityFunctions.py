import aiohttp
import asyncio
import aiosqlite
import hashlib
import json
import os.path

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

def hashData(data, algorithm):
	match algorithm:
		case "MD5":
			return hashlib.md5(data.encode()).hexdigest()
		case "SHA-1":
			return hashlib.sha1(data.encode()).hexdigest()
		case "SHA-256":
			return hashlib.sha256(data.encode()).hexdigest()
		case "SHA-512":
			return hashlib.sha512(data.encode()).hexdigest()

def verifyChecksum(data, algorithm, checksum):
	match algorithm:
		case "MD5":
			return hashlib.md5(data.encode()).hexdigest() == checksum
		case "SHA-1":
			return hashlib.sha1(data.encode()).hexdigest() == checksum
		case "SHA-256":
			return hashlib.sha256(data.encode()).hexdigest() == checksum
		case "SHA-512":
			return hashlib.sha512(data.encode()).hexdigest() == checksum
