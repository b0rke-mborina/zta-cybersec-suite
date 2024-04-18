from fastapi import FastAPI


app = FastAPI()


@app.get("/file/encrypt")
async def encryption():
	return {"status": "OK"}

@app.get("/file/decrypt")
async def decryption():
	return {"status": "OK"}
