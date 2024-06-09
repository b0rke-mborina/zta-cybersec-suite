import aiohttp
import asyncio
import hashlib
import html
import re
import base64
from Crypto.Cipher import AES, DES, DES3, Blowfish
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
		return ""

def decryptTripleDES(ciphertext, key):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = DES3.adjust_key_parity(key.encode("utf-8"))
		iv = ciphertext[:DES3.block_size]
		cipher = DES3.new(key, DES3.MODE_CFB, iv)
		plaintext = cipher.decrypt(ciphertext[DES3.block_size:])
		return plaintext.decode()
	except:
		return ""

def decryptAES(ciphertext, key, tag, nonce):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = key.encode("utf-8")
		tag = base64.b64decode(tag)
		nonce = base64.b64decode(nonce)
		cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
		plaintext = cipher.decrypt_and_verify(ciphertext, tag)
		return plaintext.decode()
	except:
		return ""

def decryptRSA(ciphertext, privateKey):
	try:
		ciphertextBytes = base64.b64decode(ciphertext.encode("utf-8"))
		privateKeyBytes = base64.b64decode(privateKey.encode("utf-8"))

		privateKey = RSA.import_key(privateKeyBytes)
		cipher = PKCS1_OAEP.new(privateKey)
		plaintext = cipher.decrypt(ciphertextBytes)
		return plaintext.decode("utf-8")
	except:
		return ""

def decryptBlowfish(ciphertext, key):
	try:
		ciphertext = base64.b64decode(ciphertext)
		key = key.encode("utf-8")
		iv = ciphertext[:Blowfish.block_size]
		cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext[Blowfish.block_size:])
		padding_length = plaintext[-1]
		plaintext = plaintext[:-padding_length]
		return plaintext.decode() # int.from_bytes(plaintext, byteorder='big')
	except:
		return ""
