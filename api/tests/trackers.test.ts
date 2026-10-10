// Unit tests for website tracker detection, the guarded page fetcher and the route
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { lookup } from 'node:dns/promises'
import { buildApp } from '../src/app'
import { fetchPage, isPrivateIp, isPublicUrl } from '@/lib/page'
import { BLOCKLIST_URL, findTrackers, pageUrls, slimBlocklist } from '@/lib/trackers'

// Every hostname resolves to a public address unless a test says otherwise
vi.mock('node:dns/promises', () => ({ lookup: vi.fn() }))
const publicDns = [{ address: '93.184.215.14', family: 4 }]
beforeEach(() => {
  vi.mocked(lookup).mockResolvedValue(publicDns as never)
})

const tds = {
  trackers: {
    'googletagmanager.com': {
      default: 'block',
      owner: { name: 'Google Ads' },
      categories: ['Tag Manager'],
    },
    'facebook.net': {
      default: 'ignore',
      owner: { name: 'Facebook, Inc.' },
      rules: [{ rule: 'facebook\\.net/.*/fbevents\\.js' }],
    },
    'stripe.com': { default: 'ignore', owner: { name: 'Stripe, Inc.' } },
    'hotjar.com': {
      default: 'block',
      owner: { name: 'Hotjar Ltd' },
      rules: [{ rule: 'hotjar\\.com/allowed', action: 'ignore' }, { rule: '([' }],
    },
    'excdn.net': { default: 'block', owner: { name: 'Example Corp' } },
    'reddit.com': { default: 'block', owner: { name: 'Reddit Inc.' } },
  },
  domains: { 'example-corp.com': 'Example Corp', 'excdn.net': 'Example Corp' },
}
const list = slimBlocklist(tds)
const found = (html: string, page = 'https://example.com/') =>
  findTrackers(html, page, list).map((t) => t.domain)

const GTM =
  "<script>j.src='https://www.googletagmanager.com/gtm.js?id='+i;" +
  "})(window,document,'script','dataLayer','GTM-AB12');</script>"

describe('slimBlocklist', () => {
  it('keeps owner, categories, default and rules, plus domain owners', () => {
    expect(list.entities['excdn.net']).toBe('Example Corp')
    expect(list.trackers['googletagmanager.com']).toEqual({
      owner: 'Google Ads',
      categories: ['Tag Manager'],
      block: true,
      rules: [],
    })
  })

  it('rejects a blocklist with no trackers', () => {
    expect(() => slimBlocklist({})).toThrow('Tracker blocklist was empty')
  })
})

describe('pageUrls', () => {
  const urls = (html: string) => pageUrls(html, 'https://example.com/').map(String)

  it('collects tag sources, quoted or not, and URLs in inline scripts', () => {
    const html =
      '<img src="/a.png"><iframe src="https://x.com/f"></iframe>' +
      '<script src=https://cdn.z.com/t.js async></script>' +
      '<script>load("//cdn.y.com/s.js")</script>'
    expect(urls(html)).toEqual([
      'https://example.com/a.png',
      'https://x.com/f',
      'https://cdn.z.com/t.js',
      'https://cdn.y.com/s.js',
    ])
  })

  it('ignores page text, JSON blocks, prefetch hints and comments', () => {
    const html =
      '<p>We block https://www.googletagmanager.com for you</p>' +
      '<script type="application/json">{"u":"https://www.googletagmanager.com/gtm.js"}</script>' +
      '<link rel="dns-prefetch" href="https://www.googletagmanager.com">' +
      '<!-- <script src="https://www.googletagmanager.com/gtm.js"></script> -->'
    expect(urls(html)).toEqual([])
  })

  it('skips inline mentions of linked pages, but keeps loads', () => {
    const html =
      '<a href="https://www.reddit.com/r/example/">Reddit</a>' +
      '<script type="application/ld+json">{"sameAs":["https://x.com/me"]}</script>' +
      '<script>self.__next_f.push(["https://reddit.com/r/example","https://x.com/me"]);' +
      's.src="https://www.redditstatic.com/ads/pixel.js"</script>'
    expect(urls(html)).toEqual(['https://www.redditstatic.com/ads/pixel.js'])
  })
})

describe('findTrackers', () => {
  it('finds a tracker loaded by an inline snippet', () => {
    expect(findTrackers(GTM, 'https://example.com/', list)).toEqual([
      {
        domain: 'googletagmanager.com',
        owner: 'Google Ads',
        categories: ['Tag Manager'],
      },
    ])
  })

  it('uses rules before the default', () => {
    const pixel = '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
    const sdk = '<script src="https://connect.facebook.net/en_US/sdk.js"></script>'
    const allowed = '<script src="https://static.hotjar.com/allowed.js"></script>'
    expect(found(pixel)).toEqual(['facebook.net'])
    expect(found(sdk)).toEqual([])
    expect(found(allowed)).toEqual([])
  })

  it('skips ignored and unlisted domains, and survives a broken rule', () => {
    const html =
      '<script src="https://js.stripe.com/v3/"></script>' +
      '<script src="https://plausible.io/js/script.js"></script>' +
      '<script src="https://static.hotjar.com/c/hotjar-1.js"></script>'
    expect(found(html)).toEqual(['hotjar.com'])
  })

  it('treats the tracker on its own site as first party', () => {
    expect(found(GTM, 'https://tagmanager.googletagmanager.com/')).toEqual([])
  })

  it("treats a company's own tracker domains as first party", () => {
    const html = '<script src="https://cdn.excdn.net/t.js"></script>'
    expect(found(html, 'https://www.example-corp.com/')).toEqual([])
    expect(found(html)).toEqual(['excdn.net'])
  })

  it('never matches built-in object keys as domains', () => {
    const html =
      '<script src="https://a.__proto__/x.js"></script><img src="//b.constructor/p">'
    expect(found(html, 'https://c.hasownproperty/')).toEqual([])
  })

  it('ignores inline mentions of pages the site links to, like social profiles', () => {
    const link = '<a href="https://www.reddit.com/r/example">Reddit</a>'
    const data =
      '<script>self.__next_f.push(["https://www.reddit.com/r/example"])</script>'
    expect(found(link + data)).toEqual([])
    expect(found(data)).toEqual(['reddit.com'])
    expect(found(link + '<img src="https://www.reddit.com/r/example">')).toEqual([
      'reddit.com',
    ])
  })

  it('reports each domain once, sorted', () => {
    const html = GTM + GTM + '<script src="https://static.hotjar.com/c/h.js"></script>'
    expect(found(html)).toEqual(['googletagmanager.com', 'hotjar.com'])
  })

  it('ignores relative and malformed URLs', () => {
    expect(found('<script src="/gtm.js"></script><img src="http://[bad">')).toEqual([])
  })
})

describe('isPublicUrl', () => {
  const ok = (url: string) => isPublicUrl(new URL(url))

  it('allows public http(s) hosts', () => {
    expect(ok('https://example.com/path?q=1')).toBe(true)
    expect(ok('http://sub.example.org')).toBe(true)
  })

  it('refuses IPs, local names, custom ports, credentials and other schemes', () => {
    for (const url of [
      'http://127.0.0.1',
      'http://169.254.169.254/latest/meta-data',
      'http://0x7f.1',
      'http://[::1]/',
      'http://localhost',
      'http://localhost.',
      'http://app.localhost',
      'http://metadata.google.internal',
      'http://printer.local',
      'http://router.lan',
      'https://example.com:8443',
      'https://user:pass@example.com',
      'ftp://example.com',
      'file:///etc/passwd',
    ]) {
      expect(ok(url), url).toBe(false)
    }
  })
})

describe('isPrivateIp', () => {
  it('flags private, loopback, link-local and mapped addresses', () => {
    for (const ip of [
      '10.1.2.3',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '127.0.0.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      '::',
      'fd12:3456::1',
      'fe80::1',
      '::ffff:127.0.0.1',
      '::127.0.0.1',
      '64:ff9b::a00:1',
    ]) {
      expect(isPrivateIp(ip), ip).toBe(true)
    }
  })

  it('allows public addresses', () => {
    for (const ip of ['93.184.215.14', '1.1.1.1', '172.32.0.1', '2606:4700::6810:84e5']) {
      expect(isPrivateIp(ip), ip).toBe(false)
    }
  })
})

const html = (body: BodyInit) =>
  new Response(body, { headers: { 'content-type': 'text/html' } })
const redirect = (location: string) =>
  new Response(null, { status: 301, headers: { location } })

describe('fetchPage', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('follows public redirects by hand and reports the final URL', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(redirect('/en/'))
      .mockResolvedValueOnce(html('<p>hi</p>'))
    vi.stubGlobal('fetch', fetchMock)
    expect(await fetchPage('https://example.com')).toEqual({
      url: 'https://example.com/en/',
      html: '<p>hi</p>',
    })
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: 'manual' })
  })

  it('refuses a redirect to a private address', async () => {
    const fetchMock = vi.fn().mockResolvedValue(redirect('http://127.0.0.1/admin'))
    vi.stubGlobal('fetch', fetchMock)
    await expect(fetchPage('https://example.com')).rejects.toMatchObject({ status: 400 })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('refuses a public name that resolves to a private address', async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: '::1', family: 6 }] as never)
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(fetchPage('http://localtest.me/')).rejects.toMatchObject({ status: 400 })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('treats a failed DNS lookup as unreachable', async () => {
    vi.mocked(lookup).mockRejectedValue(new Error('ENOTFOUND'))
    vi.stubGlobal('fetch', vi.fn())
    await expect(fetchPage('https://nope.example.com')).rejects.toMatchObject({
      status: 502,
    })
  })

  it('refuses a private URL without fetching it', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(fetchPage('http://localhost/')).rejects.toMatchObject({ status: 400 })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('gives up after too many redirects', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () => redirect('/loop')),
    )
    await expect(fetchPage('https://example.com')).rejects.toMatchObject({
      message: expect.stringContaining('Too many redirects'),
    })
  })

  it('rejects error statuses, non-HTML and network failures as 502', async () => {
    for (const respond of [
      async () => new Response('nope', { status: 404 }),
      async () =>
        new Response('%PDF', { headers: { 'content-type': 'application/pdf' } }),
      async () => Promise.reject(new TypeError('fetch failed')),
    ]) {
      vi.stubGlobal('fetch', vi.fn().mockImplementation(respond))
      await expect(fetchPage('https://example.com')).rejects.toMatchObject({
        status: 502,
      })
    }
  })

  it('stops reading after 2 MB, even mid-chunk', async () => {
    const chunk = new Uint8Array(1_500_000).fill(97)
    let pulled = 0
    const body = new ReadableStream({
      pull(controller) {
        pulled++
        controller.enqueue(chunk)
      },
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(html(body)))
    const page = await fetchPage('https://example.com')
    expect(page.html.length).toBe(2_000_000)
    expect(pulled).toBeLessThan(4)
  })
})

describe('GET /v1/enrich/trackers', () => {
  const app = buildApp()
  // A Map-backed stand-in for Workers KV
  const kv = new Map<string, string>()
  const CACHE = {
    get: async (key: string) => (kv.has(key) ? JSON.parse(kv.get(key)!) : null),
    put: async (key: string, value: string) => void kv.set(key, value),
  }
  const hit = (url: string) =>
    app.fetch(
      new Request(`http://localhost/v1/enrich/trackers?url=${encodeURIComponent(url)}`),
      { CACHE },
    )

  afterEach(() => vi.unstubAllGlobals())

  // Serve the blocklist and a page, recording which URLs were requested
  const upstream = (page: Response | (() => Response)) => {
    const calls: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL) => {
        const url = String(input)
        calls.push(url)
        if (url === BLOCKLIST_URL) return Response.json(tds)
        return typeof page === 'function' ? page() : page
      }),
    )
    return calls
  }

  it('returns the trackers a page loads, and caches the result', async () => {
    const calls = upstream(() => html(GTM))
    const res = await hit('https://route-test.example.com/page?utm=1')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      finalUrl: 'https://route-test.example.com/page?utm=1',
      trackers: [
        {
          domain: 'googletagmanager.com',
          owner: 'Google Ads',
          categories: ['Tag Manager'],
        },
      ],
    })
    const again = await hit('https://route-test.example.com/page?utm=1#top')
    expect(again.status).toBe(200)
    expect(calls.filter((url) => url !== BLOCKLIST_URL)).toHaveLength(1)
  })

  it('caches each query string apart, under keys short enough for KV', async () => {
    const calls = upstream(() => html(''))
    const long = `https://route-keys.example.com/${'a'.repeat(1000)}`
    for (const url of [`${long}?x=1`, `${long}?x=2`]) {
      expect((await hit(url)).status).toBe(200)
    }
    expect(calls.filter((url) => url !== BLOCKLIST_URL)).toHaveLength(2)
    expect([...kv.keys()].every((key) => key.length <= 512)).toBe(true)
  })

  it('rejects an invalid or private URL with the error envelope', async () => {
    upstream(html(''))
    expect((await hit('not a url')).status).toBe(400)
    const res = await hit('http://127.0.0.1/')
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ error: { code: 'BAD_REQUEST' } })
  })

  it('returns a 502 envelope when the page cannot be fetched', async () => {
    upstream(new Response('down', { status: 503 }))
    const res = await hit('https://route-down.example.com/')
    expect(res.status).toBe(502)
    expect(await res.json()).toMatchObject({ error: { code: 'UPSTREAM_ERROR' } })
  })
})
