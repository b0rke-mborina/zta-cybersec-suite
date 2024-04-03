from fastapi import FastAPI


app = FastAPI()


@app.get("/digital-signature/verify")
async def digitalSignatureVerificator():
	return {"status": "OK"}

