from fastapi import FastAPI


app = FastAPI()


@app.get("/zta/governance")
async def governance():
	return { "governance": "success" }
