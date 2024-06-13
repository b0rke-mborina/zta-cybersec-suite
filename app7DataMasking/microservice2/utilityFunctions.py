import aiohttp
import asyncio
import aiosqlite
import html
import re
import base64
import os.path
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from struct import pack
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

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def storeData(dbName, userId, dataset, originalData, maskedData):
	try:
		async with aiosqlite.connect(getDbPath(dbName)) as db:
			await db.execute(
				"INSERT INTO Data (user_id, dataset, data_original, data_masked) VALUES (?, ?, ?, ?)",
				(
					userId,
					dataset,
					originalData,
					maskedData
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
		return result[2]

def encryptBlowfish(field, plaintext):
	plaintextBytes = plaintext.encode("utf-8")
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
	ciphertext = None

	if field == "dataset":
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

		if field == "dataset":
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
