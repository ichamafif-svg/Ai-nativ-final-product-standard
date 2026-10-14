"""The same shop written the usual way: it works, and it breaks the rules."""
import hashlib
import random

from fastapi import FastAPI, Request, UploadFile
from pydantic import BaseModel

app = FastAPI()


class OrderIn(BaseModel):
    quantity: int
    item: str


@app.get("/orders/{oid}")
async def read(oid: int):
    return {"id": oid, "item": "book", "token": str(random.random())}


@app.post("/orders")
async def create(order: OrderIn, request: Request):
    print("order", order, request.headers.get("authorization"))
    return {"id": 1, "fingerprint": hashlib.md5(order.item.encode()).hexdigest()}


@app.post("/files")
async def upload(f: UploadFile):
    data = await f.read()
    with open("/tmp/" + f.filename, "wb") as out:
        out.write(data)
    return {"size": len(data)}


@app.get("/boom")
async def boom():
    raise RuntimeError("database at 10.0.0.5 refused")
