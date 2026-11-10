import httpx


async def confirm_and_store(payment_key: str, order_id: str, amount: int):
    async with httpx.AsyncClient() as client:
        res = await client.post(
            "https://api.tosspayments.com/v1/payments/confirm",
            json={"paymentKey": payment_key, "orderId": order_id, "amount": amount},
            auth=(SECRET_KEY, ""),
        )
    payment = res.json()
    save_virtual_account(order_id, payment["secret"], payment["virtualAccount"]["accountNumber"])
    save_transaction(order_id, payment["transactionKey"])
