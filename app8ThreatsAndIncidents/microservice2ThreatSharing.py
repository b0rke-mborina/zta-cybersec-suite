from fastapi import FastAPI


app = FastAPI()


@app.get("/intelligence/threats")
async def threats():
	return { "threats": "success" }
