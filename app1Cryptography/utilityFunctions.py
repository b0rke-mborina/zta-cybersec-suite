from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, DES, DES3, Blowfish
from struct import pack
from Crypto.PublicKey import RSA
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
			"INSERT INTO Log (timestamp, level, logger_source, user_id, request, error_message) VALUES (?, ?, ?, ?, ?, ?)",
			(
				dataItem.timestamp,
				dataItem.level,
				dataItem.logger_source,
				dataItem.user_id,
				dataItem.request,
				dataItem.error_message
			)
		)
		await db.commit()

def getDbPath(dbFilename):
	baseDir = os.path.dirname(os.path.abspath(__file__))
	dbPath = os.path.join(baseDir, dbFilename)
	return dbPath

async def getKey(userId, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		cursor = await db.cursor()
		await cursor.execute("SELECT * FROM Key WHERE user_id = ?", (userId, ))
		results = await cursor.fetchall()
		print("numberOfKeys", len(results))
		return results[0].key if len(results) == 1 else ""

async def storeKey(userId, key, dbName):
	async with aiosqlite.connect(getDbPath(dbName)) as db:
		await db.execute(
			"INSERT INTO Key (user_id, key) VALUES (?, ?)",
			(userId, key)
		)
		await db.commit()

def encrypt(algorithm, plaintext, key):
	match algorithm:
		case "DES":
			return encryptDES(plaintext)
		case "TripleDES":
			return encryptTripleDES(plaintext)
		case "AES":
			return encryptAES(plaintext)
		case "RSA":
			return encryptRSA(plaintext)
		case "Blowfish":
			return encryptBlowfish(plaintext)

def encryptDES(plaintext):
	key = b'8Bkey_ph'
	cipher = DES.new(key, DES.MODE_OFB)
	ciphertext = cipher.iv + cipher.encrypt(plaintext.encode())
	print(key)
	return ciphertext

def encryptTripleDES(plaintext):
	key = DES3.adjust_key_parity(get_random_bytes(24))
	cipher = DES3.new(key, DES3.MODE_CFB)
	ciphertext = cipher.iv + cipher.encrypt(plaintext.encode())
	print(key)
	return ciphertext

def encryptAES(plaintext):
	key = get_random_bytes(16)
	cipher = AES.new(key, AES.MODE_EAX)
	ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
	print(cipher.nonce)
	print(key)
	return ciphertext

def encryptRSA(plaintext):
	key = RSA.generate(2048)
	ciphertext = key.export_key(passphrase=plaintext, pkcs=8,protection="scryptAndAES128-CBC")
	print(key)
	return ciphertext

def encryptBlowfish(plaintext):
	key = b'KEY_PLACEHOLDER'
	bs = Blowfish.block_size
	cipher = Blowfish.new(key, Blowfish.MODE_CBC)
	plen = bs - len(plaintext.encode()) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(plaintext.encode() + padding)
	print(key)
	return ciphertext

def decrypt(algorithm, ciphertext, key):
	match algorithm:
		case "DES":
			return "ciphertext"
		case "TripleDES":
			return "ciphertext"
		case "AES":
			return "ciphertext"
		case "RSA":
			return "ciphertext"
		case "Blowfish":
			return "ciphertext"

def decryptDES():
	pass

def decryptTripleDES():
	pass

def decryptAES():
	pass

def decryptRSA():
	pass

def decryptBlowfish():
	pass
