import aiohttp
import asyncio
import hashlib
import html
import re
import base64
from Crypto.Cipher import AES, DES, DES3, Blowfish
from struct import pack
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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
	ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
	return (
		base64.b64encode(ciphertext).decode("utf-8"),
		base64.b64encode(tag).decode("utf-8"),
		base64.b64encode(cipher.nonce).decode("utf-8")
	)

def encryptRSA(plaintext, keyLength):
	key = RSA.generate(keyLength)
	privateKeyStr = key.export_key().decode()
	publicKeyStr = key.publickey().export_key().decode()

	publicKey = RSA.import_key(publicKeyStr)
	cipher = PKCS1_OAEP.new(publicKey)
	ciphertext = cipher.encrypt(plaintext.encode("utf-8"))

	return (
		base64.b64encode(ciphertext).decode("utf-8"),
		base64.b64encode(privateKeyStr.encode("utf-8")).decode("utf-8"),
		base64.b64encode(publicKeyStr.encode("utf-8")).decode("utf-8")
	)

def encryptBlowfish(plaintext, key):
	plaintext, key = plaintext.encode("utf-8"), key.encode("utf-8")
	bs = Blowfish.block_size
	cipher = Blowfish.new(key, Blowfish.MODE_CBC)
	plen = bs - len(plaintext) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(plaintext + padding)
	return (base64.b64encode(ciphertext).decode("utf-8"), None, None)
