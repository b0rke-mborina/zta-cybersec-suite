from fastapi import FastAPI


app = FastAPI()


@app.get("/password/store")
async def storage():
	return {"status": "OK"}

