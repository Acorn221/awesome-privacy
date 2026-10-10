/**
 * Finds the third-party trackers a web page loads
 * Using DuckDuckGo's Tracker Blocklist (CC BY-NC-SA 4.0)
 * Script, iframe and image sources, plus URLs in inline scripts
 */

import { ApiError } from '@/lib/errors'

export const BLOCKLIST_URL =
  'https://staticcdn.duckduckgo.com/trackerblocking/v5/current/extension-tds.json'

interface Rule {
  rule: string
  action?: string
}

interface TdsTracker {
  default?: string
  owner?: { name?: string }
  categories?: string[]
  rules?: Rule[]
}

interface Tds {
  trackers?: Record<string, TdsTracker>
  domains?: Record<string, string>
}

// Slimmed blocklist entry, keyed by tracker domain
export interface Tracker {
  owner: string
  categories: string[]
  block: boolean
  rules: Rule[]
}

export interface Blocklist {
  trackers: Record<string, Tracker>
  // Domain to owning company, so a company's own domains count as first party
  entities: Record<string, string>
}

export interface FoundTracker {
  domain: string
  owner: string
  categories: string[]
}

const COMMENT_RE = /<!--[\s\S]*?-->/g
const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi
const SRC_RE = /<(?:script|iframe|img)\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)/gi
const HREF_RE = /<a\b[^>]*?\bhref\s*=\s*["']?([^"'\s>]+)/gi
const JSON_TYPE_RE = /(?:^|\s)type\s*=\s*["']?[^"'\s>]*json/i
const URL_RE = /(?:https?:)?\/\/[a-z0-9.-]+\.[a-z]{2,}[^\s"'`<>()\\]*/gi

// Keep only the fields we match on, so the cached copy stays small
export const slimBlocklist = (tds: Tds): Blocklist => {
  if (!tds?.trackers) {
    throw new ApiError('UPSTREAM_ERROR', 'Tracker blocklist was empty', 502)
  }
  const trackers: Record<string, Tracker> = {}
  for (const [domain, entry] of Object.entries(tds.trackers)) {
    trackers[domain] = {
      owner: entry.owner?.name ?? '',
      categories: entry.categories ?? [],
      block: entry.default === 'block',
      rules: (entry.rules ?? []).map(({ rule, action }) => ({ rule, action })),
    }
  }
  return { trackers, entities: tds.domains ?? {} }
}

const toUrl = (raw: string, base: string) => {
  try {
    return new URL(raw, base)
  } catch {
    return null
  }
}

const toUrls = (raws: string[], base: string) =>
  raws.map((raw) => toUrl(raw, base)).filter((url): url is URL => url !== null)

// Host and path, so a link and a mention of the same page compare equal
const pageOf = (url: URL) =>
  url.hostname.replace(/^www\./, '') + url.pathname.replace(/\/$/, '')

// Tag sources plus URLs inside inline scripts, so mentions in text or JSON don't count.
// Inline mentions of pages the site links to (like social profiles in framework data)
// are links rather than loads, so are skipped, as is anything commented out.
export const pageUrls = (html: string, base: string) => {
  const live = html.replace(COMMENT_RE, '')
  const links = [...live.matchAll(HREF_RE)].map((match) => match[1])
  const inline: string[] = []
  for (const [, attrs, body] of live.matchAll(SCRIPT_RE)) {
    const target = JSON_TYPE_RE.test(attrs) ? links : inline
    target.push(...(body.match(URL_RE) ?? []))
  }
  const linked = new Set(toUrls(links, base).map(pageOf))
  const loaded = toUrls(
    [...live.matchAll(SRC_RE)].map((match) => match[1]),
    base,
  )
  return [...loaded, ...toUrls(inline, base).filter((url) => !linked.has(pageOf(url)))]
}

// The entry for a host or its nearest listed parent domain
const nearest = <T>(host: string, map: Record<string, T>) => {
  const labels = host.split('.')
  for (let i = 0; i < labels.length - 1; i++) {
    const domain = labels.slice(i).join('.')
    if (Object.hasOwn(map, domain)) return { domain, value: map[domain] }
  }
  return null
}

const ruleMatches = (rule: string, url: string) => {
  try {
    return new RegExp(rule, 'i').test(url)
  } catch {
    return false
  }
}

// DuckDuckGo's verdict, the first matching rule wins, else the domain's default
const isBlocked = (url: string, tracker: Tracker) => {
  const rule = tracker.rules.find((r) => ruleMatches(r.rule, url))
  return rule ? rule.action !== 'ignore' : tracker.block
}

// Blocked third-party trackers on a page, one per tracker domain
export const findTrackers = (html: string, pageUrl: string, list: Blocklist) => {
  const pageHost = new URL(pageUrl).hostname
  const pageEntity = nearest(pageHost, list.entities)?.value
  const found = new Map<string, FoundTracker>()
  for (const url of pageUrls(html, pageUrl)) {
    const match = nearest(url.hostname, list.trackers)
    if (!match || found.has(match.domain)) continue
    const sameEntity =
      pageEntity !== undefined &&
      nearest(match.domain, list.entities)?.value === pageEntity
    const firstParty =
      sameEntity || pageHost === match.domain || pageHost.endsWith(`.${match.domain}`)
    if (firstParty || !isBlocked(url.href, match.value)) continue
    const { owner, categories } = match.value
    found.set(match.domain, { domain: match.domain, owner, categories })
  }
  return [...found.values()].sort((a, b) => a.domain.localeCompare(b.domain))
}
