// Third-party trackers a web page loads, classified by DuckDuckGo's Tracker Blocklist
import { createRoute, z } from '@hono/zod-openapi'
import { fetchJson } from '@/lib/fetch'
import { fetchPage } from '@/lib/page'
import { BLOCKLIST_URL, findTrackers, slimBlocklist } from '@/lib/trackers'
import { freshSeconds } from '@/lib/cache/freshness'
import { newApp } from '@/lib/openapi'
import { ErrorResponse, Ok, TrackersReportSchema } from '@/schemas'

const app = newApp()

const FRESH_TTL = freshSeconds('trackers')
const BLOCKLIST_TTL = freshSeconds('trackerBlocklist')

const route = createRoute({
  method: 'get',
  path: '/enrich/trackers',
  tags: ['Enrichment'],
  summary: 'Website trackers',
  description:
    "Third-party trackers a web page loads, as classified by DuckDuckGo's " +
    'Tracker Blocklist (CC BY-NC-SA 4.0). Only the HTML is checked, so trackers ' +
    'that other scripts load later are not seen.',
  request: { query: z.object({ url: z.string().url() }) },
  responses: {
    200: Ok(TrackersReportSchema),
    400: ErrorResponse,
    401: ErrorResponse,
    500: ErrorResponse,
    502: ErrorResponse,
  },
})

// Short fixed-length digest, as a full URL could exceed KV's 512-byte key limit
const sha256 = async (text: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// Cache key is the host plus a hash of the full URL, the blocklist is shared by all pages
app.openapi(route, async (c) => {
  const { url } = c.req.valid('query')
  const { hostname, origin, pathname, search } = new URL(url)
  const data = await c.var.storage.fetch(
    `trackers:${hostname}:${await sha256(origin + pathname + search)}`,
    FRESH_TTL,
    async () => {
      const [page, blocklist] = await Promise.all([
        fetchPage(url),
        c.var.storage.fetch('trackers:blocklist', BLOCKLIST_TTL, async () =>
          slimBlocklist(await fetchJson(BLOCKLIST_URL, { timeoutMs: 15000 })),
        ),
      ])
      return {
        finalUrl: page.url,
        trackers: findTrackers(page.html, page.url, blocklist),
      }
    },
  )
  return c.json(data, 200)
})

export default app
