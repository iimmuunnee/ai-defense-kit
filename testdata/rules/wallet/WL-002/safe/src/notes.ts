// signTransaction(req.body) 처럼 쓰면 안 된다
/* sendTransaction(ctx.request.body) */
const body = req.body;
const tx = validateTx(body);
await signer.signMessage(tx.message);
