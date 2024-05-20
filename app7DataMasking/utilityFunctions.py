import aiohttp
import asyncio
import aiosqlite
import copy
import json
import os.path
from faker import Faker
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

async def storeData(dbName, userId, dataset, originalData, maskedData):
	try:
		async with aiosqlite.connect(getDbPath(dbName)) as db:
			await db.execute(
				"INSERT INTO Data (user_id, dataset, data_original, data_masked) VALUES (?, ?, ?, ?)",
				(
					userId,
					dataset,
					json.dumps(originalData),
					json.dumps(maskedData)
				)
			)
			await db.commit()
	except:
		raise RequestValidationError("Dataset name must be unique.")

async def retrieveData(dbName, userId, dataset):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM Data WHERE user_id = ? AND dataset = ?",
			(userId, dataset)
		)
		result = await cursor.fetchone()
		return json.loads(result[2])

def maskData(data):
	print(data)
	fake = Faker()
	maskedData = copy.deepcopy(data)
	for i in range(len(maskedData)):
		for j in range(len(maskedData[i])):
			if maskedData[i][j] is None:
				maskedData[i][j] = "MASKED"
			elif isinstance(maskedData[i][j], bool):
				maskedData[i][j] = fake.boolean()
			elif isinstance(maskedData[i][j], int):
				maskedData[i][j] = fake.random_int()
			elif isinstance(maskedData[i][j], float):
				maskedData[i][j] = fake.random_number()
			elif isinstance(maskedData[i][j], str):
				maskedData[i][j] = fake.word()
			else:
				maskedData[i][j] = "MASKED"
	return maskedData
