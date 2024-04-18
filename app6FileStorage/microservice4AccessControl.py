from fastapi import FastAPI


app = FastAPI()


@app.get("/file/access-control")
async def accessControl():
	return {"status": "OK"}
