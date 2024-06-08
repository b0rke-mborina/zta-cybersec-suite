import aiohttp
import asyncio
import hashlib
import html
import re
import base64
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

def encryptData(data):
	result = {}
	for field, value in data.items():
		result[field] = encryptBlowfish(field, value)
	return result

def encryptBlowfish(field, plaintext):
	plaintextBytes = intToBytes(plaintext) if isIntValue(field) else plaintext.encode("utf-8")
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
	ciphertext = None

	if useDeterministicCryptography(field):
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

def decryptData(data):
	result = {}
	for field, value in data.items():
		result[field] = decryptBlowfish(field, value)
	return result

def decryptBlowfish(field, ciphertext):
	try:
		ciphertextBytes = base64.b64decode(ciphertext)
		key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
		plaintextBytes = None

		if useDeterministicCryptography(field):
			cipher = Blowfish.new(key, Blowfish.MODE_ECB)
			plaintextBytes = unpad(cipher.decrypt(ciphertextBytes), Blowfish.block_size)
		else:
			iv = ciphertextBytes[:Blowfish.block_size]
			cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
			plaintextBytes = cipher.decrypt(ciphertextBytes[Blowfish.block_size:])
			paddingLength = plaintextBytes[-1]
			plaintextBytes = plaintextBytes[:-paddingLength]

		plaintext = bytesToInt(plaintextBytes) if isIntValue(field) else plaintextBytes.decode("utf-8")
		return plaintext
	except:
		return ""

def intToBytes(intData):
	return intData.to_bytes((intData.bit_length() + 7) // 8, byteorder='big')

def bytesToInt(byteData):
	return int.from_bytes(byteData, byteorder='big')

def hashData(data):
	return hashlib.sha512(data.encode()).hexdigest()

def isIntValue(field):
	intFields = {
		"logger_source", "user_id", "is_allowed", "request_count",
		"current_app_id", "auth_source_app_id", "is_user_authenticated_additionally"
	}
	return field in intFields

def useDeterministicCryptography(field):
	deterministicFields = {
		"user_id", "role", "username", "key", "token", "filename", "dataset", "severity",
		"password_hash", "jwt", "auth_source_app_id", "is_user_authenticated_additionally", 
		"task", "auth_type", "token_key"
	}
	return field in deterministicFields
