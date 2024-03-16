from fastapi import FastAPI

app = FastAPI()


@app.get("/cryptography/key/get")
def getKey():
	return {"key get": "OK"}

@app.post("/cryptography/key/store")
def storeKey():
	return {"key store": "OK"}
