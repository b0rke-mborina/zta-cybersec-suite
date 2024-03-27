from fastapi import FastAPI


app = FastAPI()


@app.get("/auth-generator/verify")
async def read_root():
	return {"status": "OK"}

