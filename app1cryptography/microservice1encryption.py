from fastapi import FastAPI

app = FastAPI()


@app.get("/cryptography/encrypt")
def encryption():
	return {"encryption": "OK"}


@app.get("/encrypt/{item_id}")
def read_item(item_id: int):
	return {"item_id": item_id, "q": 111}
