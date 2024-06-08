import aiohttp
import asyncio
import aiosqlite
import datetime
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

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def handleACLTask(dbName, data):
	match data.task:
		case "eZ9FPVVabeN6dDFRZ9itdA==":
			if data.user_id == "35oIObfdlDo=":
				return [False, False]
			else:
				tasks = [
					handleAuthorization(dbName, data.user_id, data.user_role),
					checkIfPossibleDosAtack("ztaACL.db", data.user_id, data.is_user_authenticated_additionally)
				]
				return await asyncio.gather(*tasks)
		case "r+KhlYVgRAQABXy35o6JOCACeHZG6q5o":
			await denyAccessToAll(dbName)
			return ["", ""]
		case "r+KhlYVgRAQI7B9eX5vQoBZazil7VuSO":
			await denyAccessToUsers(dbName)
			return ["", ""]
		case "r+KhlYVgRAQI7B9eX5vQoKm6HFXK1u4G":
			await denyAccessToUser(dbName, data.user_id)
			return ["", ""]

async def denyAccessToAll(dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute("UPDATE ACL SET is_allowed = '35oIObfdlDo=' WHERE role = '3DoxBhFdBD8=' OR role = '4I1FoHuYuxc='") # 'user' or 'admin'
		await db.commit()

async def denyAccessToUsers(dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute("UPDATE ACL SET is_allowed = '35oIObfdlDo=' WHERE role = '3DoxBhFdBD8='") # 'user'
		await db.commit()

async def denyAccessToUser(dbName, userId):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE ACL SET is_allowed = '35oIObfdlDo=' WHERE user_id = ?",
			(userId, )
		)
		await db.commit()

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
		return result[2] == "eMviHPAW92g=" # is_allowed == 1

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
			return result[2] == "eMviHPAW92g=" # is_allowed == 1

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
