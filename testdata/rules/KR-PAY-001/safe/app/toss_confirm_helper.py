from toss_sdk import TossClient


def confirm_and_store(client: TossClient, payment_key: str, order_id: str, amount: int):
    payment = client.confirm(payment_key, order_id, amount)
    save_virtual_account(order_id, payment["secret"])
    save_transaction(order_id, payment["transactionKey"])
