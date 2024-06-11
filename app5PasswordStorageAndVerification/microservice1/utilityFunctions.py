import aiohttp
import asyncio
import aiosqlite
import hashlib
import html
import re
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

def getAuthData(headers):
	jwt = headers.get("jwt")
	username = headers.get("username")
	password = headers.get("password")

	authData = {
		"jwt": jwt if jwt is not None and jwt != "" else ""
	}
	if username is not None and username != "" and password is not None and password != "":
		authData["username"] = username
		authData["password_hash"] = hashData(password)
	
	return authData

def hashData(data):
	return hashlib.sha512(data.encode()).hexdigest()

def hashPassword(password):
	algorithm = "bcrypt"
	salt = bcrypt.gensalt()
	passwordHash = bcrypt.hashpw(password.encode('utf-8'), salt)
	return (passwordHash, salt, algorithm)
