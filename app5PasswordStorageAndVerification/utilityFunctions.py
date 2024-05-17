import aiohttp
import asyncio
import aiosqlite
import json
import os.path
import bcrypt
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

async def storePasswordHash(dbName, userId, username, passwordHash, salt, algorithm):
	try:
		async with aiosqlite.connect(getDbPath(dbName)) as db:
			await db.execute(
				"INSERT INTO PasswordHash (user_id, username, password_hash, salt, algorithm) VALUES (?, ?, ?, ?, ?)",
				(
					userId,
					username,
					passwordHash,
					salt,
					algorithm
				)
			)
			await db.commit()
	except:
		raise RequestValidationError("Username must be unique.")

async def getPasswordHashInfo(dbName, userId, username):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM PasswordHash WHERE user_id = ? AND username = ?",
			(userId, username)
		)
		result = await cursor.fetchall()
		print(result)
		return result

async def updatePasswordHash(dbName, userId, username, passwordHash, salt, algorithm):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"UPDATE PasswordHash SET password_hash = ?, salt = ?, algorithm = ? WHERE user_id = ? AND username = ?",
			(
				passwordHash,
				salt,
				algorithm,
				userId,
				username
			)
		)
		await db.commit()

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

def hashPassword(password):
	algorithm = "bcrypt"
	salt = bcrypt.gensalt()
	passwordHash = bcrypt.hashpw(password.encode('utf-8'), salt)
	return (passwordHash, salt, algorithm)

def hashPasswordWithSalt(password, salt):
	algorithm = "bcrypt"
	passwordHash = bcrypt.hashpw(password.encode('utf-8'), salt.encode("utf-8"))
	return (passwordHash, salt, algorithm)

def validatePassword(password):
	passwordPolicies = {
		'minLength': 8,
		'requireUppercase': True,
		'requireLowercase': True,
		'requireDigits': True,
		'requireSpecialCharacters': True,
		'specialCharacters': "!@#$%^&*()_-+=<>?/"
	}
	brokenPolicies = []

	if len(password) < passwordPolicies.get('minLength', 8):
		brokenPolicies.append("Password length should be at least {} characters.".format(passwordPolicies.get('minLength', 8)))

	if passwordPolicies.get('requireUppercase', False) and not any(char.isupper() for char in password):
		brokenPolicies.append("Password should contain at least one uppercase letter.")

	if passwordPolicies.get('requireLowercase', False) and not any(char.islower() for char in password):
		brokenPolicies.append("Password should contain at least one lowercase letter.")

	if passwordPolicies.get('requireDigits', False) and not any(char.isdigit() for char in password):
		brokenPolicies.append("Password should contain at least one digit.")

	specialCharacters = passwordPolicies.get('specialCharacters', "!@#$%^&*()_-+=<>?/")
	if passwordPolicies.get('requireSpecialCharacters', False) and not any(char in specialCharacters for char in password):
		brokenPolicies.append("Password should contain at least one special character.")
	
	return len(brokenPolicies) == 0
