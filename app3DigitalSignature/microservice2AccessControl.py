from fastapi import FastAPI


app = FastAPI()


@app.get("/digital-signature/access-control")
async def accessControler():
	return {"status": "OK"}

