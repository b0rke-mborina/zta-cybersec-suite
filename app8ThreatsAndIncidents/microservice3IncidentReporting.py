from fastapi import FastAPI


app = FastAPI()


@app.get("/intelligence/incidents")
async def incidents():
	return { "incidents": "success" }
