// naver 로그인 시작: 인가 요청에 state가 없음
export function loginUrl() {
  const clientId = process.env.NAVER_CLIENT_ID!;
  const redirect = encodeURIComponent(process.env.NAVER_REDIRECT_URI!);
  return `https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirect}`;
}
