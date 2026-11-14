import { randomBytes } from "crypto";
import { cookies } from "next/headers";

// 카카오 로그인 시작: state를 만들어 쿠키에 두고, 돌아올 때 비교한다.
export async function GET() {
  const state = randomBytes(16).toString("hex");
  (await cookies()).set("oauth_state", state, { httpOnly: true, secure: true, sameSite: "lax" });
  const clientId = process.env.KAKAO_CLIENT_ID!;
  const redirect = encodeURIComponent(process.env.KAKAO_REDIRECT_URI!);
  return Response.redirect(
    `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirect}&state=${state}`,
  );
}
