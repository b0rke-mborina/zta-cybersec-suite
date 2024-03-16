from fastapi import FastAPI

app = FastAPI()


@app.get("/cryptography/decrypt")
def decryption():
	return {"decryption": "OK"}
