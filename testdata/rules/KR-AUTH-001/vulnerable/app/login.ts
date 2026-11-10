// kakao 로그인 시작: 인가 요청에 state가 없음
export function loginUrl() {
  const clientId = process.env.KAKAO_CLIENT_ID!;
  const redirect = encodeURIComponent(process.env.KAKAO_REDIRECT_URI!);
  return `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirect}`;
}
