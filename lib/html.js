'use strict'

// Allowlist HTML sanitiser in plain JavaScript (no DOM, no Node APIs), so it runs in Electron's
// main process, in the Bare worklet and in React Native alike. Exported through
// `hugin-network/sanitize` as `sanitizeHtml`, `sanitizeText` and `escapeText`.
//
// Policy model (a subset of sanitize-html's options):
//   allowedTags            tag names kept; every other tag is removed and its text kept, except
//                          the contents of script/style/textarea/option/xmp, which are dropped
//   allowedAttributes      { tag: [names], '*': [names] }
//   allowedSchemes         URL schemes allowed in URL attributes (href, src, ...)
//   allowProtocolRelative  allow `//host/path` URLs
//   nestingLimit           deeper allowed tags are removed (text kept)
//
// The default policy is hugin-desktop's (`src/backend/utils.cjs:5-18`): no tags, no attributes.
// Some things are never kept whatever the policy says: event handler attributes (`on*`),
// `style`, `srcdoc`, `srcset`, URL attributes whose scheme is not allowed (javascript:, data:,
// vbscript:, ... unless listed), and the tags in NEVER_TAGS. Comments, CDATA sections,
// declarations and processing instructions are removed; a tag that is still open at the end of
// the input is removed with everything after it (as htmlparser2 does); the output closes every
// tag it opened.

const DEFAULT_SCHEMES = Object.freeze(['http', 'https', 'ftp', 'mailto', 'tel'])

/** hugin-desktop's sanitize-html options: `{ allowedTags: [], allowedAttributes: {} }`. */
const DEFAULT_POLICY = Object.freeze({
  allowedTags: Object.freeze([]),
  allowedAttributes: Object.freeze({}),
  allowedSchemes: DEFAULT_SCHEMES,
  allowProtocolRelative: true,
  nestingLimit: 64
})

/** Removed tags whose content is dropped as well (sanitize-html's default `nonTextTags`). */
const NON_TEXT_TAGS = new Set(['script', 'style', 'textarea', 'option', 'xmp'])

/** Tags whose content is not markup (everything up to the matching end tag is text). */
const RAW_TEXT_TAGS = new Set(['script', 'style', 'textarea', 'xmp', 'title'])

/** Raw text tags whose content still has entities decoded (RCDATA). */
const RCDATA_TAGS = new Set(['textarea', 'title'])

const VOID_TAGS = new Set([
  'area', 'base', 'basefont', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
  'param', 'source', 'track', 'wbr'
])

/** Tags never kept, even if a policy lists them. */
const NEVER_TAGS = new Set([
  'script', 'style', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base', 'meta',
  'link', 'svg', 'math', 'template', 'noscript', 'noembed', 'noframes', 'xmp', 'plaintext',
  'textarea', 'title', 'form', 'input', 'button', 'select', 'option', 'portal'
])

/** Attributes never kept, even if a policy lists them. */
const NEVER_ATTRIBUTES = new Set(['style', 'srcdoc', 'srcset'])

/** Attributes that carry a URL. */
const URL_ATTRIBUTES = new Set([
  'href', 'src', 'cite', 'action', 'formaction', 'poster', 'background', 'longdesc', 'xlink:href',
  'data', 'codebase', 'manifest', 'ping', 'usemap', 'icon'
])

const NAMED_ENTITIES = Object.freeze({
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©',
  reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', laquo: '«',
  raquo: '»', euro: '€', pound: '£', yen: '¥', cent: '¢',
  sect: '§', deg: '°', plusmn: '±', times: '×', divide: '÷',
  middot: '·', bull: '•', para: '¶', shy: '­', colon: ':', sol: '/',
  lpar: '(', rpar: ')', semi: ';', comma: ',', period: '.', excl: '!', quest: '?',
  num: '#', percnt: '%', equals: '=', grave: '`', Tab: '\t', NewLine: '\n'
})

const ENTITY_RE = /&(#[0-9]{1,8}|#[xX][0-9a-fA-F]{1,8}|[a-zA-Z][a-zA-Z0-9]{1,31});/g

function fromCodePoint(cp) {
  if (!Number.isFinite(cp) || cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '�'
  return String.fromCodePoint(cp)
}

/**
 * Decodes numeric entities and a set of common named entities (each `&...;` once, so
 * `&amp;lt;` becomes the text `&lt;`). Unknown named entities stay as written.
 */
function decodeEntities(s) {
  return s.replace(ENTITY_RE, (m, body) => {
    if (body[0] === '#') {
      const hex = body[1] === 'x' || body[1] === 'X'
      return fromCodePoint(parseInt(body.slice(hex ? 2 : 1), hex ? 16 : 10))
    }
    const v = NAMED_ENTITIES[body]
    return v === undefined ? m : v
  })
}

/** Escapes text for HTML element content and quoted attribute values. */
function escapeText(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// ---------------------------------------------------------------------------------------------
// tokenizer

const isAlpha = (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
const isSpace = (c) => c === 32 || c === 9 || c === 10 || c === 12 || c === 13

/**
 * Splits `s` into tokens: { type: 'text', text, raw, rcdata }, { type: 'open', name, attrs,
 * selfClosing }, { type: 'close', name }. Comments, CDATA, declarations and processing
 * instructions produce no token. An unterminated tag or comment ends the input.
 */
function tokenize(s) {
  const tokens = []
  const n = s.length
  let i = 0
  let textStart = 0

  const flushText = (end) => {
    if (end > textStart) tokens.push({ type: 'text', text: s.slice(textStart, end), raw: false })
  }
  const skipTo = (from, seq) => {
    const end = s.indexOf(seq, from)
    return end === -1 ? -1 : end + seq.length
  }

  while (i < n) {
    const lt = s.indexOf('<', i)
    if (lt === -1) break
    const c = s.charCodeAt(lt + 1)

    if (isAlpha(c)) {
      const tag = parseOpenTag(s, lt + 1)
      flushText(lt)
      if (!tag) return tokens // unterminated tag: drop it and the rest
      tokens.push({ type: 'open', name: tag.name, attrs: tag.attrs, selfClosing: tag.selfClosing })
      i = textStart = tag.end
      if (RAW_TEXT_TAGS.has(tag.name) && !tag.selfClosing) {
        const re = new RegExp('</' + tag.name + '(?=[\\s/>])', 'gi')
        re.lastIndex = i
        const m = re.exec(s)
        const end = m ? m.index : n
        if (end > i) tokens.push({ type: 'text', text: s.slice(i, end), raw: true, rcdata: RCDATA_TAGS.has(tag.name) })
        i = textStart = end
      }
      continue
    }

    if (c === 47 /* / */) {
      flushText(lt)
      if (isAlpha(s.charCodeAt(lt + 2))) {
        let p = lt + 2
        while (p < n && !isSpace(s.charCodeAt(p)) && s[p] !== '/' && s[p] !== '>') p++
        const name = s.slice(lt + 2, p).toLowerCase()
        const end = skipQuotedTo(s, p)
        if (end === -1) return tokens
        tokens.push({ type: 'close', name })
        i = textStart = end
      } else {
        // `</` not followed by a letter: a bogus comment up to the next `>`
        const end = skipTo(lt + 2, '>')
        if (end === -1) return tokens
        i = textStart = end
      }
      continue
    }

    if (c === 33 /* ! */) {
      flushText(lt)
      let end
      if (s.startsWith('<!--', lt)) {
        if (s.startsWith('<!-->', lt)) end = lt + 5
        else if (s.startsWith('<!--->', lt)) end = lt + 6
        else end = skipTo(lt + 4, '-->')
      } else if (s.startsWith('<![CDATA[', lt)) {
        end = skipTo(lt + 9, ']]>')
      } else {
        end = skipTo(lt + 2, '>')
      }
      if (end === -1) return tokens
      i = textStart = end
      continue
    }

    if (c === 63 /* ? */) {
      flushText(lt)
      const end = skipTo(lt + 2, '>')
      if (end === -1) return tokens
      i = textStart = end
      continue
    }

    // a `<` that does not start markup is text
    i = lt + 1
  }
  flushText(n)
  return tokens
}

/** Index after the `>` that ends a tag starting at `p`, skipping quoted values; -1 if none. */
function skipQuotedTo(s, p) {
  const n = s.length
  while (p < n) {
    const ch = s[p]
    if (ch === '>') return p + 1
    if (ch === '"' || ch === "'") {
      const q = s.indexOf(ch, p + 1)
      if (q === -1) return -1
      p = q + 1
      continue
    }
    p++
  }
  return -1
}

/** Parses `name attrs... >` from `p` (just after `<`). null when the tag is not terminated. */
function parseOpenTag(s, p) {
  const n = s.length
  const start = p
  while (p < n && !isSpace(s.charCodeAt(p)) && s[p] !== '/' && s[p] !== '>') p++
  const name = s.slice(start, p).toLowerCase()
  const attrs = []
  let selfClosing = false

  while (p < n) {
    const ch = s[p]
    if (isSpace(s.charCodeAt(p))) {
      p++
      continue
    }
    if (ch === '>') return { name, attrs, selfClosing, end: p + 1 }
    if (ch === '/') {
      selfClosing = s[p + 1] === '>'
      p++
      continue
    }
    selfClosing = false
    const nameStart = p
    p++ // the first character may be anything (even `=`), as in browsers
    while (p < n && !isSpace(s.charCodeAt(p)) && s[p] !== '/' && s[p] !== '>' && s[p] !== '=') p++
    const attrName = s.slice(nameStart, p).toLowerCase()
    while (p < n && isSpace(s.charCodeAt(p))) p++
    let value = ''
    if (s[p] === '=') {
      p++
      while (p < n && isSpace(s.charCodeAt(p))) p++
      const q = s[p]
      if (q === '"' || q === "'") {
        const end = s.indexOf(q, p + 1)
        if (end === -1) return null
        value = s.slice(p + 1, end)
        p = end + 1
      } else {
        const vStart = p
        while (p < n && !isSpace(s.charCodeAt(p)) && s[p] !== '>') p++
        value = s.slice(vStart, p)
      }
    }
    attrs.push([attrName, decodeEntities(value)])
  }
  return null
}

// ---------------------------------------------------------------------------------------------
// policy and output

function normalizePolicy(policy) {
  const p = policy || DEFAULT_POLICY
  const allowedTags = new Set((p.allowedTags || []).map((t) => String(t).toLowerCase()))
  const attrs = {}
  for (const [tag, list] of Object.entries(p.allowedAttributes || {})) {
    attrs[String(tag).toLowerCase()] = new Set((list || []).map((a) => String(a).toLowerCase()))
  }
  return {
    allowedTags,
    allowedAttributes: attrs,
    allowedSchemes: new Set((p.allowedSchemes || DEFAULT_SCHEMES).map((x) => String(x).toLowerCase())),
    allowProtocolRelative: p.allowProtocolRelative !== undefined ? !!p.allowProtocolRelative : true,
    nestingLimit: typeof p.nestingLimit === 'number' ? p.nestingLimit : DEFAULT_POLICY.nestingLimit
  }
}

function tagAllowed(name, p) {
  return /^[a-z][a-z0-9-]*$/.test(name) && p.allowedTags.has(name) && !NEVER_TAGS.has(name)
}

/** True when a URL attribute value is relative or uses an allowed scheme. */
function urlAllowed(value, p) {
  // Browsers ignore control characters and whitespace inside a scheme (`java\tscript:`).
  const v = value.replace(/[\u0000-\u0020\u007f-\u009f\u00ad\u200b-\u200f\u2028\u2029\ufeff]/g, '')
  if (v.startsWith('//') || v.startsWith('\\\\') || v.startsWith('/\\') || v.startsWith('\\/')) {
    return p.allowProtocolRelative
  }
  const m = /^([a-z][a-z0-9+.-]*):/i.exec(v)
  if (m) return p.allowedSchemes.has(m[1].toLowerCase())
  // A `:` before any `/`, `?` or `#` would be read as a scheme by some parser: refuse it.
  const colon = v.indexOf(':')
  if (colon === -1) return true
  const stop = v.search(/[/?#]/)
  return stop !== -1 && stop < colon
}

function attributesOf(tag, attrs, p) {
  const allowed = p.allowedAttributes[tag]
  const any = p.allowedAttributes['*']
  const seen = new Set()
  let out = ''
  for (const [name, value] of attrs) {
    if (seen.has(name)) continue // the first of duplicate attributes wins, as in browsers
    seen.add(name)
    if (!/^[a-z][a-z0-9_:.-]*$/.test(name)) continue
    if (name.startsWith('on') || NEVER_ATTRIBUTES.has(name)) continue
    if (!(allowed && allowed.has(name)) && !(any && any.has(name))) continue
    if (URL_ATTRIBUTES.has(name) && !urlAllowed(value, p)) continue
    out += ' ' + name + '="' + escapeText(value) + '"'
  }
  return out
}

function run(input, policy, textOnly) {
  const p = textOnly ? normalizePolicy(DEFAULT_POLICY) : normalizePolicy(policy)
  const tokens = tokenize(input)
  const stack = []
  let out = ''
  let discardTag = null
  let discardDepth = 0

  for (const tok of tokens) {
    if (discardTag !== null) {
      if (tok.type === 'open' && tok.name === discardTag && !tok.selfClosing) discardDepth++
      else if (tok.type === 'close' && tok.name === discardTag && --discardDepth === 0) discardTag = null
      continue
    }

    if (tok.type === 'text') {
      const text = tok.raw && !tok.rcdata ? tok.text : decodeEntities(tok.text)
      out += textOnly ? text : escapeText(text)
      continue
    }

    if (tok.type === 'open') {
      const allowed = !textOnly && tagAllowed(tok.name, p)
      if (!allowed) {
        if (NON_TEXT_TAGS.has(tok.name) && !tok.selfClosing && !VOID_TAGS.has(tok.name)) {
          discardTag = tok.name
          discardDepth = 1
        }
        continue
      }
      if (stack.length >= p.nestingLimit) continue
      const isVoid = VOID_TAGS.has(tok.name)
      out += '<' + tok.name + attributesOf(tok.name, tok.attrs, p) + (isVoid ? ' />' : '>')
      if (!isVoid) stack.push(tok.name)
      continue
    }

    // close
    if (textOnly || !stack.includes(tok.name)) continue
    while (stack.length) {
      const name = stack.pop()
      out += '</' + name + '>'
      if (name === tok.name) break
    }
  }
  while (stack.length) out += '</' + stack.pop() + '>'
  return out
}

/**
 * Sanitises `input` to HTML that keeps only what `policy` allows (default: no tags at all, so
 * the result is the escaped text). The result is safe to insert as HTML.
 */
function sanitizeHtml(input, policy) {
  const s = typeof input === 'string' ? input : input === undefined || input === null ? '' : String(input)
  return run(s, policy, false)
}

/**
 * hugin-desktop's `sanitizeHtml` (`utils.cjs:5-18`): the text content with all markup removed
 * and entities decoded, i.e. sanitize-html with no allowed tags followed by un-escaping. The
 * result is plain text: render it as text (or `escapeText` it), never as HTML. Non-string
 * values are returned unchanged, as desktop does.
 */
function sanitizeText(input) {
  if (typeof input !== 'string') return input
  const text = run(input, DEFAULT_POLICY, true)
  // sanitize-html escapes &, < and > in text; desktop then un-escapes with these replaces, in
  // this order (so text written as `&amp;lt;` ends up as `<`, exactly as on desktop).
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/&amp;/g, '&')
    .replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/')
}

module.exports = {
  DEFAULT_POLICY,
  DEFAULT_SCHEMES,
  NON_TEXT_TAGS,
  NEVER_TAGS,
  NEVER_ATTRIBUTES,
  URL_ATTRIBUTES,
  sanitizeHtml,
  sanitizeText,
  escapeText,
  decodeEntities,
  tokenize
}
