from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/policy")
async def policy():
	return { "policy": "success" }
