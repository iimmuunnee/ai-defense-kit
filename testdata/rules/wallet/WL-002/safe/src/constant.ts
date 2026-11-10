const LOGIN_MESSAGE = "로그인 확인";
const sig = await signer.signMessage(LOGIN_MESSAGE);
await walletClient.sendTransaction({ to: ALLOWED_TO, value: 1n });
