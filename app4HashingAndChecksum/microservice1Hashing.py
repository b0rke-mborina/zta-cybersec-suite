from fastapi import FastAPI


app = FastAPI()


@app.get("/hashing/hash")
async def hashing():
	return {"status": "OK"}
