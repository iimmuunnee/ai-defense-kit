import { Wallet } from "ethers";

// 키는 서명 서비스가 들고 있고, 이 코드는 서명만 요청한다.
const w = new Wallet(signerHandle, provider);
const rpc = process.env.RPC_URL;
const publicKey = process.env.PUBLIC_KEY;
