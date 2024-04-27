from fastapi import FastAPI

app = FastAPI()


@app.get("/intelligence/report")
async def reporting():
	return { "reporting": "success" }

