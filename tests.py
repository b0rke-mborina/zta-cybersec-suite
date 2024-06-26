import pytest
import aiohttp
import re

# helper functions
async def request(session, method, url, data):
	async with session.request(method = method, url = url, headers = generateHeaders(), json = data) as response:
		return await response.json(), response.status

async def sendRequest(method, url, requestData = None):
	async with aiohttp.ClientSession() as session:
		data, status = await request(session, method, url, requestData)
		return data, status

def generateHeaders():
	return {
		"Content-Type": "application/json",
		"username": "user1",
		"password": "P@ssword1",
		"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.Fu0A7PiKntIytjlI2vs57HJfLgl3Bw90feVGF1NBG6k"
	}



# TESTS


# app 1 tests

@pytest.mark.asyncio
async def testEndpointApp1Encryption():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8001/cryptography/encrypt",
		{
			"algorithm": "RSA",
			"plaintext": "neki tekst",
			"key": "aaaabbbbccccdddd",
			"key_length": 1024
		}
	)

	assert responseStatus == 200
	assert responseData.get("encryption") == "success"
	assert re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$').match(responseData.get("ciphertext"))
	assert re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$').match(responseData.get("private_key"))
	assert re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$').match(responseData.get("public_key"))

@pytest.mark.asyncio
async def testEndpointApp1Decryption():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8002/cryptography/decrypt",
		{
			"algorithm": "RSA",
			"ciphertext": "AhCSI76mliuFC4uXopf6LPI0/YzMVr8WEu87/n1tj/ouzqvlXQQ/s/t7epZCDOdEU4vemxmOQlvpngN2WmfwQHMW4DUavd7A0oz+6XN21cHRnN0LAEMpHf7+TvRDxqQMAepPfz5m4JW48mJLgElFl90bZo6fzaqbaRuTuv7nBmc=",
			"key": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWFFJQkFBS0JnUUNaMTlIZHZUb3FuUFBWTmxvcWhzNWtUOVpuNHZkVk5vK01uLzVFbHhUL2RnL0MwYUFGCmNyOVpuZ1dndjJLVERYcVg0aFkyVlNqdXZmU2pGVUE1c2QyWmp3eEI4dVBiZ0M2cHlkVHBOMk9iQVFGTmRCRCsKYlpBL3dDT25reTJqSjZTMVY1Vzh2dWlJOWl4Y1BWK1gvbDlhOXhHTWJReXkwdkptK0EycXo2NnJWd0lEQVFBQgpBb0dBTVRBWi84V3l4VkV0Zk94RjQvYjZJb1NNVHViNG9ad3lSWW9hS0NBT0xLZTQzbGRiektJbG9DZXdNUGRBCk16aEtEQ25UWkVmU01KTTNsclVDdGUreXBCbFUrMVJiczdpNndkS2pvc1lMRjVIRGdWb0NSVXFlUW5QNHdtRlQKMEZYd0NJZDBGMmZKbXJBN0d4NktxMU1WTktSeXVBa2dPNWRmRkVocDRtUWNQdUVDUVFDOUVUU1VSK0ltVkI4QQpIR1phbXZWcVBkYnFCQVJYOWFvdmVvVWxqc013Rk40L1cyM0Zjc0lzbUNUaXF4Smd2NWd2b3lwcldYRWZRVUxHCnhKcnZGV2RwQWtFQTBFNVJIQ2pKOTU4SmxmbWk0Q0lJYW5taUE1M29CRFpFZzFxQUF0MHYyS3dVclFCdjZlSUsKTkVNc3pZeStodEg2SUptekFrSkpqTnQ5bEh6QmF4WGt2d0pBUm5VdCtnQmIxOXJMZnJnV3NMZEVzK1g5dkZIbwo2SHFsaEhJTlFuVFVhb3VzVTBJWVExZkQ0dWlEL25Dd05adlE5QmZEVENRVjB3YjRBcWpyOENNeTJRSkJBTWhBCmNmTXJOellJdXZObHdISE41ZDlPUFRWUzZVaWJUdlFqM1dwamJ1clNTekloZUhVVWE1RGdmMEsvcWkzNzBJVGsKblZWdm1qdUNpbEJrT3FFU3RBc0NRUUNTdEtJQnN6TUUrN3RnRDlrT253Mlk2SDN1a0dFOGU4VWJWQU92WHh2RApHem9BNmRQaVZHT3ZXdmJFNGxlQnF4TVpLMkpBbVNLUVhOQWpNUW1qYTNaRAotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQ==",
			"tag": "L+WNPx+SVfQNt0DLarqyJg==",
			"nonce": "IIC6djz8cbS8cvNFdHraVg=="
		}
	)

	assert responseStatus == 200
	assert responseData.get("decryption") == "success"
	assert isinstance(responseData.get("plaintext"), str) and len(responseData.get("plaintext")) > 0


# app 2 tests

@pytest.mark.asyncio
async def testEndpointApp2GenerationApiKey():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8010/auth-generator/generate/api-key"
	)

	assert responseStatus == 200
	assert responseData.get("generation") == "success"
	assert re.compile(r'^[A-Za-z0-9]{32}$').match(responseData.get("api_key"))

@pytest.mark.asyncio
async def testEndpointApp2VerificationApiKey():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8011/auth-generator/verify/api-key",
		{
			"api_key": "nStNcSLvNleIWIomyRMf650EKtDAvwfA"
		}
	)

	assert responseStatus == 200
	assert responseData.get("verification") == "success"
	assert responseData.get("is_valid") == False or responseData.get("is_valid") == True


# app 3 tests

@pytest.mark.asyncio
async def testEndpointApp3Verification():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8020/digital-signature/verify",
		{
			"public_key": "CiAgICAtLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLQogICAgTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEybktiNjlEdXpmL24zL3hkY1o1bQogICAgbjVuRTIrZEdtNzFqd3ZnNWRXNVRvUG1nL3FuZmFIS2Y5b3o2WnkxZ0tvMTJKSEJGMEo1UlpHbkpmNkQ1WTlueAogICAgNklJU3FZSHM3ajk4bUJxUzVGVnVSOVBRYkIrWnRDSFh5c25NWVdsNVFXd0dqWHpFVnBJb3BrelY0R3NsR3RWYgogICAgWlZXbEYxKytCNXBkWkw2Z01RaVNmK0FGS1l0QWtpYlJSaGZ2bUxGUWk3ZjNERkJQWUo4RDBRajJVNC9YWkpjWAogICAgRnZBbVU3d0dWYlJLNEdrbTlrM1k1RTZDMU9wOERGclRNeDVGWFI1RCtBVHVFWjNIT2JiOXMxUzdQT21PVTd2eAogICAgejdsNm9Yc2x5Z0NuMVhRZS9BczVHbmZzOG4zVHdDakZac2hOSzBWZGI0aVkzajVIZlNvRGJrOXpnMWpYeEkxOQogICAgQXdJREFRQUIKICAgIC0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
			"digital_signature": "SGVsbG8sIFdvcmxkIQ==",
			"message": "neki tekst",
			"hash_function": "sha256"
		}
	)

	assert responseStatus == 200
	assert responseData.get("verification") == "success"
	assert responseData.get("is_valid") == False


# app 4 tests

@pytest.mark.asyncio
async def testEndpointApp4Hashing():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8030/hashing/hash",
		{
			"data": "S0meth!ng",
			"algorithm": "SHA-1",
			"password": False
		}
	)

	assert responseStatus == 200
	assert responseData == {
		"hashing": "success",
		"hash": "a3953a1343f3355f1436904e290a3839792a7293"
	}

@pytest.mark.asyncio
async def testEndpointApp4Verification():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8031/hashing/verify",
		{
			"data": "S0meth!ng",
			"algorithm": "SHA-1",
			"checksum": "a3953a1343f3355f1436904e290a3839792a7293"
		}
	)

	assert responseStatus == 200
	assert responseData == {
		"verification": "success",
		"is_checksum_valid": True
	}


# app 5 tests

@pytest.mark.asyncio
async def testEndpointApp5Storage():
	responseData, responseStatus = await sendRequest(
		"POST",
		"http://127.0.0.1:8040/password/store",
		{
			"username": "useradmin2",
			"password": "P@55admin"
		}
	)

	assert responseStatus == 200
	assert responseData == { "storage": "success" }

@pytest.mark.asyncio
async def testEndpointApp5Verification():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8041/password/verify",
		{
			"username": "useradmin2",
			"password": "P@55admin"
		}
	)

	assert responseStatus == 200
	assert responseData.get("verification") == "success"
	assert responseData.get("is_valid") == True

@pytest.mark.asyncio
async def testEndpointApp5Reset():
	responseData, responseStatus = await sendRequest(
		"POST",
		"http://127.0.0.1:8042/password/reset",
		{
			"username": "useradmin2",
			"current_password": "P@55admin",
			"new_password": "P@55wordadmin"
		}
	)

	assert responseStatus == 200 
	assert responseData == { "reset": "success" }


# app 6 tests

@pytest.mark.asyncio
async def testEndpointApp6Store():
	responseData, responseStatus = await sendRequest(
		"POST",
		"http://127.0.0.1:8050/file/store",
		{
			"format": "txt",
			"filename": "file1",
			"file": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccc"
		}
	)

	assert responseStatus == 200
	assert responseData == { "storage": "success" }

@pytest.mark.asyncio
async def testEndpointApp6Retrieve():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8050/file/retrieve",
		{
			"filename": "file1"
		}
	)

	assert responseStatus == 200
	assert responseData == {
		"storage": "success",
		"file": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccc"
	}


# app 7 tests

@pytest.mark.asyncio
async def testEndpointApp7Mask():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8060/data/mask",
		{
			"dataset": "dataset1",
			"data": [["aaa", 3, True], ["bbb", 2, None], ["ccc", 1, False]]
		}
	)

	assert responseStatus == 200
	assert responseData.get("masking") == "success"
	assert len(responseData.get("data")) == 3
	assert all(isinstance(item, list) and len(item) == 3 for item in responseData.get("data"))

@pytest.mark.asyncio
async def testEndpointApp7Unmask():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8060/data/unmask",
		{
			"dataset": "dataset1"
		}
	)

	assert responseStatus == 200
	assert responseData == {
		"unmasking": "success",
		"data": [["aaa", 3, True], ["bbb", 2, None], ["ccc", 1, False]]
	}


# app 8 tests

@pytest.mark.asyncio
async def testEndpointApp8Report():
	responseData, responseStatus = await sendRequest(
		"POST",
		"http://127.0.0.1:8070/intelligence/report",
		{
			"incident": {
				"timestamp": "2024-04-04",
				"affected_assets": ["aaa", "bbb", "ccc"],
				"attack_vectors": [["aaa"], ["bbb"], ["ccc"]],
				"malicious_code": ["aaa", "bbb", "ccc"],
				"compromised_data": ["aaa", "bbb", "ccc"],
				"indicators_of_compromise": ["aaa", "bbb", "ccc"],
				"severity": "high",
				"user_accounts_involved": ["aaa", "bbb", "ccc"],
				"logs": ["aaa", "bbb", "ccc"],
				"actions": ["aaa", "bbb", "ccc"]
			}
		}
	)

	assert responseStatus == 200
	assert responseData == { "reporting": "success" }

@pytest.mark.asyncio
async def testEndpointApp8Retrieve():
	responseData, responseStatus = await sendRequest(
		"GET",
		"http://127.0.0.1:8071/intelligence/retrieve",
		{
			"time_from": "2024-04-01",
			"time_to": "2024-04-09",
			"severity": "high"
		}
	)

	assert responseStatus == 200
	assert responseData.get("retrieval") == "success"
	assert responseData.get("data") == [
		{
			"timestamp": "2024-04-04",
			"affected_assets": ["aaa", "bbb", "ccc"],
			"attack_vectors": [["aaa"], ["bbb"], ["ccc"]],
			"malicious_code": ["aaa", "bbb", "ccc"],
			"compromised_data": ["aaa", "bbb", "ccc"],
			"indicators_of_compromise": ["aaa", "bbb", "ccc"],
			"severity": "high",
			"user_accounts_involved": ["aaa", "bbb", "ccc"],
			"logs": ["aaa", "bbb", "ccc"],
			"actions": ["aaa", "bbb", "ccc"]
		}
	]

#@pytest.mark.skip(reason = "Skipping this test now...") to skip tests
