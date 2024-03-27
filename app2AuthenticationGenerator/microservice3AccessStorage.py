from fastapi import FastAPI


app = FastAPI()


@app.get("/auth-generator/access-storage")
async def read_root():
	return {"status": "OK"}

