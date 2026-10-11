/**
 * Fetches the HTML of a public web page, for enrich routes that inspect websites.
 * Unlike fetchJson the host is arbitrary, so IPs, local names, custom ports and
 * hosts resolving to private addresses are refused, each redirect hop is
 * re-checked, and the body is capped in size.
 */

import { ApiError } from '@/lib/errors'
import { log } from '@/lib/log'

const MAX_BYTES = 2_000_000
const MAX_REDIRECTS = 5
const TIMEOUT_MS = 10000
const USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
const LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home.arpa']

export interface Page {
  // Where the page ended up, after any redirects
  url: string
  html: string
}

// Only plain http(s) on public hostnames and default ports, never IPs or local names
export const isPublicUrl = (url: URL) => {
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  return (
    ['http:', 'https:'].includes(url.protocol) &&
    !url.port &&
    !url.username &&
    !url.password &&
    host.includes('.') &&
    !/^[\d.]+$/.test(host) &&
    !host.startsWith('[') &&
    !LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix))
  )
}

// IPv4 blocks that are never public (RFC 6890): private, loopback, link-local,
// shared CGNAT, benchmarking, multicast and reserved ranges
const PRIVATE_V4: [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 3],
]

const v4ToInt = (ip: string) =>
  ip.split('.').reduce((n, part) => n * 256 + Number(part), 0)

// Special IPv6 (anything under ::, unique-local, link-local, NAT64) or private IPv4
export const isPrivateIp = (ip: string) => {
  const addr = ip.toLowerCase()
  if (addr.includes(':')) return /^(::|fc|fd|fe[89a-f]|64:ff9b:)/.test(addr)
  return PRIVATE_V4.some(
    ([base, bits]) => v4ToInt(addr) >>> (32 - bits) === v4ToInt(base) >>> (32 - bits),
  )
}

// Workers can't reach private networks, elsewhere refuse hosts that resolve to them.
// Fetch resolves again, so this blocks static records (like localtest.me), not fast rebinding.
const resolvesPrivate = async (host: string) => {
  if (globalThis.navigator?.userAgent === 'Cloudflare-Workers') return false
  const { lookup } = await import('node:dns/promises')
  const addresses = await lookup(host, { all: true })
  return addresses.some(({ address }) => isPrivateIp(address))
}

// Read at most MAX_BYTES of the body, then stop downloading
const readCapped = async (res: Response) => {
  const reader = res.body?.getReader()
  if (!reader) return ''
  const decoder = new TextDecoder()
  let html = ''
  let size = 0
  while (size < MAX_BYTES) {
    const { done, value } = await reader.read()
    if (done) break
    const chunk = value.subarray(0, MAX_BYTES - size)
    size += chunk.byteLength
    html += decoder.decode(chunk, { stream: true })
  }
  await reader.cancel()
  return html
}

export const fetchPage = async (target: string): Promise<Page> => {
  const signal = AbortSignal.timeout(TIMEOUT_MS)
  let url = new URL(target)
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (!isPublicUrl(url) || (await resolvesPrivate(url.hostname))) {
        throw new ApiError('BAD_REQUEST', `URL not allowed: ${url.hostname}`, 400)
      }
      const res = await fetch(url, {
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html' },
        redirect: 'manual',
        signal,
      })
      const location = res.headers.get('location')
      if (res.status >= 300 && res.status < 400 && location) {
        await res.body?.cancel()
        url = new URL(location, url)
        continue
      }
      // Only a 200 is the page itself, other 2xx are interstitials
      if (res.status !== 200) {
        throw new ApiError(
          'UPSTREAM_ERROR',
          `${url.hostname} returned ${res.status}`,
          502,
        )
      }
      if (!res.headers.get('content-type')?.includes('html')) {
        throw new ApiError('UPSTREAM_ERROR', `${url.hostname} did not return HTML`, 502)
      }
      return { url: url.href, html: await readCapped(res) }
    }
    throw new ApiError('UPSTREAM_ERROR', `Too many redirects from ${target}`, 502)
  } catch (caught) {
    if (caught instanceof ApiError) throw caught
    log.warn('page_fetch_failed', { host: url.hostname, err: (caught as Error).message })
    throw new ApiError('UPSTREAM_ERROR', `Could not fetch ${url.hostname}`, 502)
  }
}
