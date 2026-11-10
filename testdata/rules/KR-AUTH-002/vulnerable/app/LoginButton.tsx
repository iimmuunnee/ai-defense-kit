import { useState } from "react";

// useState만 있고 OAuth state는 없음
export function LoginButton() {
  const [state, setState] = useState("idle");
  const go = () => {
    setState("loading");
    window.location.href = `https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=${process.env.NEXT_PUBLIC_NAVER_CLIENT_ID}`;
  };
  return <button onClick={go}>{state}</button>;
}
