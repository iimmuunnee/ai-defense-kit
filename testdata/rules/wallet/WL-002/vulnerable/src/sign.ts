app.post("/sign", async (req, res) => {
  const sig = await wallet.signTransaction(req.body);
  res.json({ sig });
});
