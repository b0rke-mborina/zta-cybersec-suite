import aiohttp
import asyncio
import html
import re
import base64
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
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

def encryptFile(file):
	key = "key_placeholder1" # must be 16 chars # PLACEHOLDER
	cipher = AES.new(key.encode("utf-8"), AES.MODE_EAX)
	ciphertext, tag = cipher.encrypt_and_digest(file.encode("utf-8"))
	return (
		base64.b64encode(ciphertext).decode("utf-8"),
		base64.b64encode(key.encode("utf-8")).decode("utf-8"),
		base64.b64encode(tag).decode("utf-8"),
		base64.b64encode(cipher.nonce).decode("utf-8")
	)

def decryptFile(file, key, tag, nonce):
	file = base64.b64decode(file)
	key = base64.b64decode(key)
	tag = base64.b64decode(tag)
	nonce = base64.b64decode(nonce)
	cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
	plaintext = cipher.decrypt_and_verify(file, tag)
	return plaintext.decode()

def encryptSecret(secretBase64):
	secretBytes = base64.b64decode(secretBase64)
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER
	mode = Blowfish.MODE_CBC

	cipher = Blowfish.new(key, mode)
	bs = Blowfish.block_size
	plen = bs - len(secretBytes) % bs
	padding = [plen]*plen
	padding = pack('b'*plen, *padding)
	ciphertext = cipher.iv + cipher.encrypt(secretBytes + padding)

	return base64.b64encode(ciphertext).decode("utf-8")

def decryptSecret(secretBase64):
	ciphertextBytes = base64.b64decode(secretBase64)
	key = "KEY_PLACEHOLDER".encode("utf-8") # PLACEHOLDER

	iv = ciphertextBytes[:Blowfish.block_size]
	cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
	plaintextBytes = cipher.decrypt(ciphertextBytes[Blowfish.block_size:])
	paddingLength = plaintextBytes[-1]
	plaintextBytes = plaintextBytes[:-paddingLength]

	return base64.b64encode(plaintextBytes).decode("utf-8")
