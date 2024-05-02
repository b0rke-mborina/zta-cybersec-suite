from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/network")
async def network():
	return { "network": "success" }
