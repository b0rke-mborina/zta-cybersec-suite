import aiohttp
import asyncio
import aiosqlite
import datetime
import json
import html
import re
import base64
import os.path
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from struct import pack

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

async def storeThreat(dbName, userId, dataItem):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Threat (user_id, timestamp, affected_assets, attack_vectors, malicious_code, compromised_data, indicators_of_compromise, severity, user_accounts_involved, logs, actions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			(
				userId,
				dataItem["timestamp"],
				dataItem["affected_assets"],
				dataItem["attack_vectors"],
				dataItem["malicious_code"],
				dataItem["compromised_data"],
				dataItem["indicators_of_compromise"],
				dataItem["severity"],
				dataItem["user_accounts_involved"],
				dataItem["logs"],
				dataItem["actions"]
			)
		)
		await db.commit()

async def getThreats(dbName, timeFrom, timeTo, severity):
	async with aiosqlite.connect(getDbPath(dbName)) as conn:
		cursor = await conn.execute(
			"SELECT * FROM Threat WHERE severity = ?",
			(severity, )
		)
		data = await cursor.fetchall()
		results = []
		for dataItem in data:
			datetimeOfThreat = datetime.datetime.fromisoformat(dataItem[1]).replace(tzinfo=datetime.timezone.utc)
			datetimeFrom = datetime.datetime.fromisoformat(timeFrom).replace(tzinfo=datetime.timezone.utc)
			datetimeTo = datetime.datetime.fromisoformat(timeTo).replace(tzinfo=datetime.timezone.utc)
			if datetimeOfThreat > datetimeFrom and datetimeOfThreat < datetimeTo:
				results.append(loadThreat(dataItem))
		return results

def loadThreat(threat):
	loadedThreat = {
		"timestamp": threat[1],
		"affected_assets": json.loads(decryptBlowfish("affected_assets", threat[2])),
		"attack_vectors": json.loads(decryptBlowfish("attack_vectors", threat[3])),
		"malicious_code": json.loads(decryptBlowfish("malicious_code", threat[4])),
		"compromised_data": json.loads(decryptBlowfish("compromised_data", threat[5])),
		"indicators_of_compromise": json.loads(decryptBlowfish("indicators_of_compromise", threat[6])),
		"severity": decryptBlowfish("severity", threat[7]),
		"user_accounts_involved": json.loads(decryptBlowfish("user_accounts_involved", threat[8])),
		"logs": json.loads(decryptBlowfish("logs", threat[9])),
		"actions": json.loads(decryptBlowfish("actions", threat[10]))
	}
	return loadedThreat

def encryptData(data):
	result = {}
	for field, value in data.items():
		result[field] = encryptBlowfish(field, value)
	return result

def encryptBlowfish(field, plaintext):
	if not isinstance(plaintext, str):
		plaintext = json.dumps(plaintext)
	plaintextBytes = plaintext.encode("utf-8")
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
	ciphertext = None

	if field == "severity":
		mode = Blowfish.MODE_ECB
		cipher = Blowfish.new(key, Blowfish.MODE_ECB)
		paddedText = pad(plaintextBytes, Blowfish.block_size)
		ciphertext = cipher.encrypt(paddedText)
	else:
		mode = Blowfish.MODE_CBC
		cipher = Blowfish.new(key, mode)
		bs = Blowfish.block_size
		plen = bs - len(plaintextBytes) % bs
		padding = [plen]*plen
		padding = pack('b'*plen, *padding)
		ciphertext = cipher.iv + cipher.encrypt(plaintextBytes + padding)

	return base64.b64encode(ciphertext).decode("utf-8")

def decryptBlowfish(field, ciphertext):
	try:
		ciphertextBytes = base64.b64decode(ciphertext)
		key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
		plaintextBytes = None

		if field == "severity":
			cipher = Blowfish.new(key, Blowfish.MODE_ECB)
			plaintextBytes = unpad(cipher.decrypt(ciphertextBytes), Blowfish.block_size)
		else:
			iv = ciphertextBytes[:Blowfish.block_size]
			cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
			plaintextBytes = cipher.decrypt(ciphertextBytes[Blowfish.block_size:])
			paddingLength = plaintextBytes[-1]
			plaintextBytes = plaintextBytes[:-paddingLength]

		plaintext = plaintextBytes.decode("utf-8")
		return plaintext
	except:
		return ""
