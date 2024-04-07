from fastapi import FastAPI


app = FastAPI()


@app.get("/hashing")
async def hashing():
	return {"status": "OK"}
