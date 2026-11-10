router.post("/send", async (ctx) => {
  await walletClient.sendTransaction({ ...ctx.request.body });
});
