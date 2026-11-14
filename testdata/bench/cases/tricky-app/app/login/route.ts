import { randomBytes } from "crypto";
import { cookies } from "next/headers";

// state를 만들어 쿠키에는 넣지만, 인가 요청 주소에는 빠뜨렸다.
export async function GET() {
  const state = randomBytes(16).toString("hex");
  (await cookies()).set("oauth_state", state, { httpOnly: true });
  const clientId = process.env.KAKAO_CLIENT_ID!;
  const redirect = encodeURIComponent(process.env.KAKAO_REDIRECT_URI!);
  return Response.redirect(
    `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirect}`,
  );
}
