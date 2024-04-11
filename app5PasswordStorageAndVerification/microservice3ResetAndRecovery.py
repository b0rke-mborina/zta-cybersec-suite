from fastapi import FastAPI


app = FastAPI()


@app.get("/password/reset")
async def reset():
	return {"status": "OK"}

