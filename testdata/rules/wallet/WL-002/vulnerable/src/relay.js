const res = await fetch(approvalUrl);
const sig = await signer.signMessage(await res.json());
