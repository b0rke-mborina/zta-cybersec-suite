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

def incidentIncludesThisSystem(data):
	assets = {"CyberSecSuite", "you", "me", "this system"}
	affectedAssets = getattr(data, "affected_assets", [])
	if any(asset in assets for asset in affectedAssets):
		return True
	
	accounts = {data.user_id, data.username}
	userAccounts = getattr(data, "user_accounts_involved", [])
	if any(account in accounts for account in userAccounts):
		return True
	
	return False
