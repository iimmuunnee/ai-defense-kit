const express = require("express");
const app = express();
app.use(express.json());

app.post("/webhook/toss/vbank", (req, res) => {
  const ok = req.body.status === "DONE";
  if (ok) markDeposited(req.body.orderId, req.body.transactionKey, req.body.secret);
  res.json({ ok: true });
});
