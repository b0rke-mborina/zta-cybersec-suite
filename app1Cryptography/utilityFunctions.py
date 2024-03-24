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

def encrypt(algorithm, plaintext, key = None, key_length = None):
	match algorithm:
		case "DES":
			return encryptDES(plaintext, key)
		case "TripleDES":
			return encryptTripleDES(plaintext, key)
		case "AES":
			return encryptAES(plaintext, key)
		case "RSA":
			return encryptRSA(plaintext, key_length)
		case "Blowfish":
			return encryptBlowfish(plaintext, key)

def encryptDES(plaintext, key):
	key = key.encode()
	cipher = DES.new(key, DES.MODE_OFB)
	ciphertext = cipher.iv + cipher.encrypt(plaintext.encode())
	print(key)
	return (ciphertext, None)

def encryptTripleDES(plaintext, key):
	key = DES3.adjust_key_parity(key.encode())
	cipher = DES3.new(key, DES3.MODE_CFB)
	ciphertext = cipher.iv + cipher.encrypt(plaintext.encode())
	print(key)
	return (ciphertext, None)

def encryptAES(plaintext, key):
	key = key.encode()
	cipher = AES.new(key, AES.MODE_EAX)
	ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
	print(cipher.nonce)
	print(key)
	return (ciphertext, None)

def encryptRSA(plaintext, key_length):
	key = RSA.generate(key_length)
	ciphertext = key.export_key(passphrase=plaintext, pkcs=8,protection="scryptAndAES128-CBC")
	print(key)
	return (ciphertext, key.decode())

def encryptBlowfish(plaintext, key):
	plaintext, key = plaintext.encode(), key.encode()
	bs = Blowfish.block_size
	cipher = Blowfish.new(key, Blowfish.MODE_CBC)
	plen = bs - len(plaintext) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(plaintext + padding)
	print(key)
	return (ciphertext, None)

def decrypt(algorithm, ciphertext, key):
	match algorithm:
		case "DES":
			return decryptDES(ciphertext, key)
		case "TripleDES":
			return decryptTripleDES(ciphertext, key)
		case "AES":
			return decryptAES(ciphertext, key)
		case "RSA":
			return decryptRSA(ciphertext, key)
		case "Blowfish":
			return decryptBlowfish(ciphertext, key)

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
