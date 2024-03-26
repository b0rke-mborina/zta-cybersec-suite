from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, DES, DES3, Blowfish
from struct import pack
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import aiohttp
import asyncio
import aiosqlite
import json
import os.path
import base64

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

def encrypt(algorithm, plaintext, key = None, key_length = None):
	match algorithm:
		case "DES":
			return encryptDES(plaintext, key)
		case "TripleDES":
			return encryptTripleDES(plaintext, key)
		case "AES":
			return encryptAES(plaintext, key)
		case "RSA":
			return encryptRSA(plaintext, key) # key_length
		case "Blowfish":
			return encryptBlowfish(plaintext, key)

def encryptDES(plaintext, key):
	key = key.encode("utf-8")
	plaintext = plaintext.encode("utf-8")
	cipher = DES.new(key, DES.MODE_OFB)
	ciphertext = cipher.iv + cipher.encrypt(plaintext)
	return (base64.b64encode(ciphertext).decode("utf-8"), None, None)

def encryptTripleDES(plaintext, key):
	key = DES3.adjust_key_parity(key.encode("utf-8"))
	cipher = DES3.new(key, DES3.MODE_CFB)
	plaintext = plaintext.encode("utf-8")
	ciphertext = cipher.iv + cipher.encrypt(plaintext)
	return (base64.b64encode(ciphertext).decode("utf-8"), None, None)

def encryptAES(plaintext, key):
	key = key.encode("utf-8")
	cipher = AES.new(key, AES.MODE_EAX)
	# cipher.update(b"header")
	ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
	print(cipher.nonce)
	print(tag)
	print(key)
	"""
	{
	"algorithm": "AES",
	"plaintext": "neki tekst",
	"key": "aaaabbbbccccdddd",
	"key_length": 2048
	}
	"""
	return (base64.b64encode(ciphertext).decode("utf-8"), base64.b64encode(tag).decode("utf-8"), base64.b64encode(cipher.nonce).decode("utf-8"))

def encryptRSA(plaintext, publicKey):
	key = RSA.import_key(publicKey)
	cipher_rsa = PKCS1_OAEP.new(key)
	ciphertext = cipher_rsa.encrypt(plaintext.encode("utf-8"))
	return base64.b64encode(ciphertext).decode("utf-8")
	"""key = RSA.generate(key_length)
	ciphertext = key.export_key(passphrase=plaintext, pkcs=8, protection="scryptAndAES128-CBC")
	print(ciphertext)
	print(key)
	return (ciphertext.decode(), key, None)"""

def encryptBlowfish(plaintext, key):
	plaintext, key = plaintext.encode("utf-8"), key.encode("utf-8")
	bs = Blowfish.block_size
	cipher = Blowfish.new(key, Blowfish.MODE_CBC)
	plen = bs - len(plaintext) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(plaintext + padding)
	print(key)
	return (base64.b64encode(ciphertext).decode("utf-8"), None, None)

def decrypt(algorithm, ciphertext, key, tag = None, nonce = None):
	match algorithm:
		case "DES":
			return decryptDES(ciphertext, key)
		case "TripleDES":
			return decryptTripleDES(ciphertext, key)
		case "AES":
			return decryptAES(ciphertext, key, tag, nonce)
		case "RSA":
			return decryptRSA(ciphertext, key)
		case "Blowfish":
			return decryptBlowfish(ciphertext, key)

def decryptDES(ciphertext, key):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = key.encode("utf-8")
		iv = ciphertext[:DES.block_size]
		cipher = DES.new(key, DES.MODE_OFB, iv)
		plaintext = cipher.decrypt(ciphertext[DES.block_size:])
		return plaintext.decode()
	except:
		return None

def decryptTripleDES(ciphertext, key):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = DES3.adjust_key_parity(key.encode("utf-8"))
		iv = ciphertext[:DES3.block_size]
		cipher = DES3.new(key, DES3.MODE_CFB, iv)
		plaintext = cipher.decrypt(ciphertext[DES3.block_size:])
		return plaintext.decode()
	except:
		return None

def decryptAES(ciphertext, key, tag, nonce):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = key.encode("utf-8")
		print("tag", tag)
		tag = base64.b64decode(tag) # base64.b64decode(tag) tag.encode("utf-8")
		nonce = base64.b64decode(nonce) # base64.b64decode(nonce) nonce.encode("utf-8")
		# nonce = ciphertext[:AES.block_size]
		# iv = ciphertext[:AES.block_size]
		cipher = AES.new(key, AES.MODE_EAX, nonce = nonce) # , mac_len=iv
		# cipher.update(b"header")
		# print("ciphertext", ciphertext)
		# print("key", key)
		# print("nonce", nonce)
		# print("cipher", cipher)
		# print("HEREEEEEEEEEEEEEEEEEEE")
		plaintext = cipher.decrypt_and_verify(ciphertext, tag) # ciphertext[AES.block_size:]
		# print("HEREEEEEEEEEEEEEEEEEEE")
		# print("plaintext", plaintext)
		"""
		{
		"algorithm": "AES",
		"ciphertext": "76GqirefBGET2w==",
		"key": "aaaabbbbccccdddd",
		"tag": "hk3gTn7UWM6/TtYAyc/Vsg==",
		"nonce": "hk3gTn7UWM6/TtYAyc/Vsg=="
		}
		"""
		return plaintext.decode()
	except Exception as e:
		print("e", e)
		return None

def decryptRSA(ciphertext, privateKey):
	print("hereeeeeeeeeeeeeeee")
	ciphertext = base64.b64decode(ciphertext)
	privateKey = privateKey.encode() # base64.b64decode(privateKey)
	key = RSA.import_key(privateKey)
	cipher_rsa = PKCS1_OAEP.new(key)
	decrypted_message = cipher_rsa.decrypt(base64.b64decode(ciphertext))
	return decrypted_message.decode()
	"""key = RSA.import_key(privateKey)
	plaintext = key.decrypt(ciphertext, None)
	return plaintext.decode()"""

def decryptBlowfish(ciphertext, key):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = key.encode("utf-8")
		iv = ciphertext[:Blowfish.block_size]
		cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
		padding_length = plaintext[-1]
		plaintext = plaintext[:-padding_length]
		return plaintext.decode()
	except:
		return None
