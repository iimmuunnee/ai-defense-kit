# Next.js: 미들웨어 말고 데이터 가까이에서도 인증 확인하기

미들웨어(Proxy)의 확인은 1차 거름망으로 두고, 데이터를 읽거나 바꾸는 곳에서 세션을 다시 검증하세요. Next.js 공식 가이드도 "it should not be your only line of defense in protecting your data."라고 적습니다.

아래는 이해를 돕는 예시입니다(그대로 복사해 쓰는 코드가 아니라 모양을 보여 주는 예시이며, `getSession`과 `db`는 각자의 인증 방식과 데이터 계층에 맞게 바꿔야 합니다).

## 1. 데이터 접근 계층(DAL)에서 확인하기

```ts
// lib/dal.ts (예시)
import 'server-only'
import { cache } from 'react'
import { redirect } from 'next/navigation'
import { getSession } from '@/lib/session' // 예시: 세션을 서버에서 검증하는 함수

export const verifySession = cache(async () => {
  const session = await getSession()
  if (!session?.userId) redirect('/login')
  return { userId: session.userId }
})

export async function getOrders() {
  const { userId } = await verifySession()
  return db.orders.findMany({ where: { userId } }) // 예시: 내 것만 읽기
}
```

## 2. 라우트 핸들러에서 확인하기

```ts
// app/api/orders/route.ts (예시)
import { getOrders } from '@/lib/dal'

export async function GET() {
  const orders = await getOrders() // 안에서 세션을 다시 확인함
  return Response.json(orders)
}
```

## 3. 서버 액션에서 확인하기

```ts
// app/actions.ts (예시)
'use server'
import { verifySession } from '@/lib/dal'

export async function deleteOrder(id: string) {
  const { userId } = await verifySession() // 여기서도 세션을 다시 확인
  await db.orders.delete({ where: { id, userId } })
}
```

## 4. 함께 하면 좋은 것

- `next`를 쓰고 있는 버전대(12, 13, 14, 15)의 수정 버전 이상으로 올리세요. 12.x는 12.3.5, 13.x는 13.5.9, 14.x는 14.2.25, 15.x는 15.2.3 이상입니다. 취약한 버전은 의존성 점검이 따로 알려 줍니다.
- 버전을 바로 올릴 수 없다면, 권고문대로 `x-middleware-subrequest` 헤더가 있는 외부 요청이 앱에 닿지 못하게 프록시나 방화벽에서 막으세요. Vercel에 배포한 앱은 권고문에 따르면 자동으로 보호됩니다.
