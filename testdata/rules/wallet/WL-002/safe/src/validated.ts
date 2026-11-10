const tx = parseTransfer(req.body);
const sig = await wallet.signTransaction(tx);
const sig2 = await wallet.signTransaction(schema.parse(req.body));
