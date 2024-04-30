import datetime
import aiohttp
import asyncio
import aiosqlite
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

async def storeThreat(dbName, userId, dataItem):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Threat (user_id, timestamp, affected_assets, attack_vectors, malicious_code, compromised_data, indicators_of_compromise, severity, user_accounts_involved, logs, actions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			(
				userId,
				dataItem.timestamp,
				json.dumps(dataItem.affected_assets),
				json.dumps(dataItem.attack_vectors),
				json.dumps(dataItem.malicious_code),
				json.dumps(dataItem.compromised_data),
				json.dumps(dataItem.indicators_of_compromise),
				dataItem.severity.value,
				json.dumps(dataItem.user_accounts_involved),
				json.dumps(dataItem.logs),
				json.dumps(dataItem.actions)
			)
		)
		await db.commit()

async def getThreats(dbName, timeFrom, timeTo, severity):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM Data WHERE AND severity = ?",
			(severity)
		)
		data = await cursor.fetchall()
		results = []
		for dataItem in data:
			datetimeofThreat = datetime.datetime.fromisoformat(dataItem[1]).replace(tzinfo=datetime.timezone.utc)
			if datetimeofThreat > timeFrom and datetimeofThreat < timeTo:
				results.append(loadThreat(dataItem))
		return results

def loadThreat(threat):
	loadedThreat = {
		"timestamp": threat.timestamp,
		"affected_assets": json.loads(threat.affected_assets),
		"attack_vectors": json.loads(threat.attack_vectors),
		"malicious_code": json.loads(threat.malicious_code),
		"compromised_data": json.loads(threat.compromised_data),
		"indicators_of_compromise": json.loads(threat.indicators_of_compromise),
		"severity": threat.severity,
		"user_accounts_involved": json.loads(threat.user_accounts_involved),
		"logs": json.loads(threat.logs),
		"actions": json.loads(threat.actions)
	}
	return loadedThreat

async def validateIncidentData(data):
	pass

async def validateThreatRequest(data):
	pass

async def checkIfIncidentIncludesThisSystem(data):
	pass
