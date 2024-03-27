from fastapi import FastAPI


app = FastAPI()


@app.get("/auth-generator/logging")
async def read_root():
	return {"status": "OK"}

