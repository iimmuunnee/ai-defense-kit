import { cookies } from 'next/headers'

export default async function Page() {
  const store = await cookies()
  return <div>{store.get('theme')?.value}</div>
}
