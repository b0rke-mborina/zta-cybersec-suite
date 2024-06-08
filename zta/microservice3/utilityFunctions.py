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

async def checkUserNetworkSegment(dbName, data):
	result = False
	if data.user_id == "35oIObfdlDo=": # == 0
		return False
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM Network WHERE user_id = ?",
			(data.user_id, )
		)
		dataFromDb = await cursor.fetchone()

		currentDatetime = datetime.datetime.now(datetime.timezone.utc)
		lastAuthenticated = datetime.datetime.fromisoformat(dataFromDb[2]).replace(tzinfo=datetime.timezone.utc)
		lastAuthenticationExpires = lastAuthenticated + datetime.timedelta(hours=1)
		if (data.auth_source_app_id == dataFromDb[1] and currentDatetime < lastAuthenticationExpires) or data.is_user_authenticated_additionally == "eMviHPAW92g=": # == 1
			result = True

	if data.is_user_authenticated_additionally == "eMviHPAW92g=": # == 1
		await updateUserNetworkSegment(dbName, data, currentDatetime)
	
	return result

async def updateUserNetworkSegment(dbName, data, currentDatetime):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE Network SET current_app_id = ?, last_authenticated = ? WHERE user_id = ?",
			(
				data.auth_source_app_id,
				currentDatetime.isoformat(),
				data.user_id
			)
		)
		await db.commit()
