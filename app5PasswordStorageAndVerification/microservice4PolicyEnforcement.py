from fastapi import FastAPI


app = FastAPI()


@app.get("/password/policy")
async def policy():
	return {"status": "OK"}

