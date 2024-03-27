from fastapi import FastAPI

app = FastAPI()


@app.get("/auth-generator/generate")
async def read_root():
	return {"status": "OK"}

