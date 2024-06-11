import aiohttp
import asyncio
import html
import re

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

def validatePassword(password):
	passwordPolicies = {
		'minLength': 8,
		'requireUppercase': True,
		'requireLowercase': True,
		'requireDigits': True,
		'requireSpecialCharacters': True,
		'specialCharacters': "!@#$%^&*()_-+=<>?/"
	}
	brokenPolicies = []

	if len(password) < passwordPolicies.get('minLength', 8):
		brokenPolicies.append("Password length should be at least {} characters.".format(passwordPolicies.get('minLength', 8)))

	if passwordPolicies.get('requireUppercase', False) and not any(char.isupper() for char in password):
		brokenPolicies.append("Password should contain at least one uppercase letter.")

	if passwordPolicies.get('requireLowercase', False) and not any(char.islower() for char in password):
		brokenPolicies.append("Password should contain at least one lowercase letter.")

	if passwordPolicies.get('requireDigits', False) and not any(char.isdigit() for char in password):
		brokenPolicies.append("Password should contain at least one digit.")

	specialCharacters = passwordPolicies.get('specialCharacters', "!@#$%^&*()_-+=<>?/")
	if passwordPolicies.get('requireSpecialCharacters', False) and not any(char in specialCharacters for char in password):
		brokenPolicies.append("Password should contain at least one special character.")
	
	return len(brokenPolicies) == 0
