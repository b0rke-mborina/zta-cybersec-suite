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

def handleProblem(problem):
	match problem:
		case "security_breach":
			handleSecurityBreach()
		case "dos_attack":
			handleDosAttack()
		case "data_inconsistency":
			handleDataInconsistency()
		case "data_compromise":
			handleDataCompromise()
		case "infrastructure_integrity_violation":
			handleInfrastructureIntegrityViolation()
		case "partial_system_failure":
			handlePartialSystemFailure()
		case "total_system_failure":
			handleTotalSystemFailure()

def handleSecurityBreach():
	pass

def handleDosAttack():
	pass

def handleDataInconsistency():
	pass

def handleDataCompromise():
	pass

def handleInfrastructureIntegrityViolation():
	pass

def handlePartialSystemFailure():
	pass

def handleTotalSystemFailure():
	pass

def handleUserAuthentication(data):
	match data.auth_method.value:
		case "username_and_password":
			handleSecurityBreach()
		case "jwt":
			handleDosAttack()

def authenticateUserWithUsernameAndPassword():
	pass

def authenticateUserWithJwt():
	pass

async def updateUserNetworkSegment(data):
	pass

async def getAuthData():
	pass

async def handleAuthorization():
	pass

async def checkIfPossibleDosAtack():
	pass

def encryptData(data):
	pass

def decryptData(data):
	pass

async def reportToAdmin():
	pass
