import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const locales = ['ko', 'en']

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  const hasLocale = locales.some((l) => pathname.startsWith(`/${l}/`) || pathname === `/${l}`)
  if (hasLocale) return NextResponse.next()
  return NextResponse.redirect(new URL(`/ko${pathname}`, request.url))
}
