import pika

connection = pika.BlockingConnection(pika.ConnectionParameters("localhost")) # host = "localhost", port = 8089
channel = connection.channel()

channel.queue_declare(queue = "notifications")

def callback(ch, method, properties, body):
	print("Received notification:", body.decode())

channel.basic_consume(
	queue = "notifications",
	on_message_callback = callback,
	auto_ack = True
)

print("Waiting for notifications...")

channel.start_consuming()