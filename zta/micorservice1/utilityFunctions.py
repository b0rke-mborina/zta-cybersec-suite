import aiohttp
import asyncio
import datetime
import os
import pika

async def request(session, method, url, data):
	async with session.request(method = method, url = url, json = data) as response:
			return await response.json()

async def sendRequest(method, url, reqData):
	async with aiohttp.ClientSession() as session:
		task = request(session, method, url, reqData)
		result = await asyncio.gather(task)
		return result

async def handleProblem(request, data, response):
	tasks = [
		reportToAdmin(data.problem),
		sendRequest(
			"post",
			os.getenv("URL_MONITORING_MICROSERVICE"),
			{
				"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
				"level": "INFO",
				"logger_source": 1,
				"user_id": data.user_id,
				"request": f"Request {request.url} {request.method} {request.headers} {request.query_params} {request.path_params} {await request.body()}".translate(str.maketrans("\"'{}:", "_____")),
				"response": str(response).translate(str.maketrans("\"'{}:", "_____")),
				"error_message": data.problem
			}
		)
	]
	
	if data.problem in ["security_breach", "infrastructure_integrity_violation"]:
		tasks.append(
			sendRequest(
				"get",
				os.getenv("URL_ACL_MICROSERVICE"),
				{
					"task": "deny_access_to_all"
				}
			)
		)
	elif data.problem in ["data_inconsistency", "partial_system_failure", "total_system_failure"]:
		tasks.append(
			sendRequest(
				"get",
				os.getenv("URL_ACL_MICROSERVICE"),
				{
					"task": "deny_access_to_users"
				}
			)
		)
	elif data.problem == "dos_attack":
		tasks.append(
			sendRequest(
				"get",
				os.getenv("URL_ACL_MICROSERVICE"),
				{
					"task": "deny_access_to_user",
					"user_id": data.user_id
				}
			)
		)
	
	await asyncio.gather(*tasks)

async def reportToAdmin(problem):
	connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
	channel = connection.channel()

	channel.queue_declare(queue = "notifications")
	channel.basic_publish(
		exchange = "",
		routing_key = "notifications",
		body = problem
	)

	print("Notification sent")
	connection.close()
