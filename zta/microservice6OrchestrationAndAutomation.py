from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/orchestration")
async def orchestration():
	return { "orchestration": "success" }

@app.get("/zta/automation")
async def automation():
	return { "automation": "success" }
