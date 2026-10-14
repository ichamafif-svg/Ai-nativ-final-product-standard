"""The shop, on Standard's building blocks: every rule holds by using a block."""
from fastapi import Depends, FastAPI, UploadFile

from standard_blocks import Values
from standard_blocks.access import Access
from standard_blocks.files import Files
from standard_blocks.input import Input, Output
from standard_blocks.log import event
from standard_blocks.runtime import install
from standard_blocks.session import Oidc
from standard_blocks.web import secure_app

values = Values.from_env()
app = secure_app(FastAPI(docs_url=None, redoc_url=None, openapi_url=None), values)
oidc = Oidc("https://idp.example/realms/shop", "shop", "https://shop.example/auth/callback", values).bind(app)
access = Access(oidc.current_user, values).bind(app)
files = Files(values)
install(app)


class OrderIn(Input):
    quantity: int
    item: str


class OrderOut(Output):
    id: int
    item: str


@app.get("/orders/{oid}", dependencies=[Depends(access.allow("orders.read"))], response_model=OrderOut)
async def read(oid: int):
    return OrderOut(id=oid, item="book")


@app.post("/orders", dependencies=[Depends(access.allow("orders.create"))], response_model=OrderOut)
async def create(order: OrderIn):
    event("order.created", item=order.item)
    return OrderOut(id=1, item=order.item)


@app.post("/files", dependencies=[Depends(access.allow("files.upload"))])
async def upload(f: UploadFile, user=Depends(oidc.current_user)):
    return {"id": await files.receive(f, owner=user.id)}
