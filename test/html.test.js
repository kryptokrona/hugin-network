'use strict'

const test = require('brittle')
const { sanitizeHtml, sanitizeText, escapeText } = require('../lib/sanitize.js')
const { load } = require('./fixtures/legacy-desktop-html.js')

const desktopSanitize = load() // null on Bare (sanitize-html is a Node devDependency)

// Inputs with the plain text hugin-desktop's `sanitizeHtml` (utils.cjs:5-18) returns for them.
const TEXT_CASES = [
  ['hello', 'hello'],
  ['a < b > c', 'a < b > c'],
  ['<b>bold</b> text', 'bold text'],
  ['<script>alert(1)</script>after', 'after'],
  ['<style>body{}</style>x', 'x'],
  ['<img src=x onerror=alert(1)>', ''],
  ['<a href="javascript:alert(1)">click</a>', 'click'],
  ['<svg onload=alert(1)>', ''],
  ['&lt;script&gt;', '<script>'],
  ['AT&T', 'AT&T'],
  ['Tom &amp; Jerry', 'Tom & Jerry'],
  ['&amp;lt;', '<'],
  ['<!-- c -->visible', 'visible'],
  ['x<y', 'x'],
  ['I <3 you', 'I <3 you'],
  ['<textarea><b>x</b></textarea>y', 'y'],
  ['<option>a</option>b', 'b'],
  ['&#106;&#97;', 'ja'],
  ['<div>a</div><p>b</p>', 'ab'],
  ['<<b>>', '<>'],
  ['<scr<script>ipt>alert(1)</script>', 'ipt>alert(1)'],
  ['emoji \u{1F600} ünïcode', 'emoji \u{1F600} ünïcode'],
  ['it\'s "quoted"', 'it\'s "quoted"']
]

test('sanitizeText: the plain text desktop produces', (t) => {
  for (const [input, expected] of TEXT_CASES) t.is(sanitizeText(input), expected, JSON.stringify(input))
  t.is(sanitizeText(42), 42, 'non-strings are returned unchanged (desktop)')
  t.is(sanitizeText(undefined), undefined)
})

test('sanitizeText: same output as desktop sanitize-html policy', { skip: !desktopSanitize }, (t) => {
  for (const [input] of TEXT_CASES) {
    t.is(sanitizeText(input), desktopSanitize(input), JSON.stringify(input))
  }
})

test('sanitizeHtml, default policy (desktop): no markup survives, text is escaped', (t) => {
  t.is(sanitizeHtml('<b>hi</b> <script>x</script>'), 'hi ')
  t.is(sanitizeHtml('a < b && c > d'), 'a &lt; b &amp;&amp; c &gt; d')
  t.is(sanitizeHtml('it\'s "q"'), 'it&#39;s &quot;q&quot;')
  t.is(sanitizeHtml('&lt;script&gt;'), '&lt;script&gt;', 'entities are decoded once, then escaped again')
  t.is(sanitizeHtml(undefined), '')
  t.is(sanitizeHtml(5), '5')
  for (const [input] of TEXT_CASES) {
    t.absent(sanitizeHtml(input).includes('<'), 'no tag in ' + JSON.stringify(input))
  }
})

const POLICY = {
  allowedTags: ['b', 'i', 'em', 'strong', 'code', 'pre', 'br', 'p', 'a', 'img', 'ul', 'li'],
  allowedAttributes: { a: ['href', 'title'], img: ['src', 'alt'] }
}

test('sanitizeHtml: allowed markup is kept and normalized', (t) => {
  const cases = [
    ['<b>bold</b> and <i>it</i>', '<b>bold</b> and <i>it</i>'],
    ['<B>x</B>', '<b>x</b>'],
    ['line<br>next<br/>end', 'line<br />next<br />end'],
    ['<a href="https://example.com/a?b=1&amp;c=2" title="t">l</a>', '<a href="https://example.com/a?b=1&amp;c=2" title="t">l</a>'],
    ['<a href="/relative/path">r</a>', '<a href="/relative/path">r</a>'],
    ['<a href="mailto:a@b.c">m</a>', '<a href="mailto:a@b.c">m</a>'],
    ['<a href="//cdn.example/x">p</a>', '<a href="//cdn.example/x">p</a>'],
    ['<img src="https://x/y.png" alt="pic">', '<img src="https://x/y.png" alt="pic" />'],
    ['<p>unclosed <b>bold', '<p>unclosed <b>bold</b></p>'],
    ['<b><i>x</b></i>', '<b><i>x</i></b>'],
    ['</b>stray', 'stray'],
    ['<div>kept text</div>', 'kept text'],
    ['<ul><li>one<li>two</ul>', '<ul><li>one<li>two</li></li></ul>']
  ]
  for (const [input, expected] of cases) t.is(sanitizeHtml(input, POLICY), expected, input)
})

test('sanitizeHtml: markup vectors', (t) => {
  const cases = [
    ['<script>alert(1)</script>', ''],
    ['<SCRIPT SRC=//other/x.js></SCRIPT>', ''],
    ['<script>alert(1)</script >after', 'after'],
    ['<img src=x onerror=alert(1)>', '<img src="x" />'],
    ['<img src="x" onerror="alert(1)" ONLOAD="y">', '<img src="x" />'],
    ['<img src="data:image/svg+xml,<svg onload=alert(1)>">', '<img />'],
    ['<img """><script>alert(1)</script>">', '<img />&quot;&gt;'],
    ['<img src=x onerror=alert(1)', ''],
    ['<a href="javascript:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="JaVaScRiPt:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="  javascript:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="jav&#x09;ascript:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="jav\tascript:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="java\u0000script:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="&#106;avascript:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="&#x6A;avascript:alert(1)">x</a>', '<a>x</a>'],
    ['<a href="javascript&colon;alert(1)">x</a>', '<a>x</a>'],
    ['<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>', '<a>x</a>'],
    ['<a href="vbscript:msgbox(1)">x</a>', '<a>x</a>'],
    ['<a href="x:y">x</a>', '<a>x</a>'],
    ['<a href="x" title=\'a"b\'>q</a>', '<a href="x" title="a&quot;b">q</a>'],
    ['<a title="x" onclick="y" href="https://ok">q</a>', '<a title="x" href="https://ok">q</a>'],
    ['<a href="https://ok" href="javascript:alert(1)">q</a>', '<a href="https://ok">q</a>'],
    ['<b onmouseover="alert(\'x\')">hi</b>', '<b>hi</b>'],
    ['<svg onload=alert(1)><b>x</b></svg>', '<b>x</b>'],
    ['<svg><script>alert(1)</script></svg>', ''],
    ['<math><mi xlink:href="javascript:alert(1)">x</mi></math>', 'x'],
    ['<iframe src="javascript:alert(1)"></iframe>', ''],
    ['<object data="javascript:alert(1)"></object>', ''],
    ['<style>@import "//other"</style>', ''],
    ['<textarea><script>alert(1)</script></textarea>', ''],
    ['<!--<img src=x onerror=alert(1)>-->ok', 'ok'],
    ['<!--><img src=x>', '<img src="x" />'],
    ['<![CDATA[<script>alert(1)</script>]]>ok', 'ok'],
    ['<!DOCTYPE html><b>x</b>', '<b>x</b>'],
    ['<?xml version="1.0"?><b>x</b>', '<b>x</b>'],
    ['safe <b>bold <a href="https://x', 'safe <b>bold </b>'],
    ['<scr<script>ipt>alert(1)</script>', 'ipt&gt;alert(1)'],
    ['&lt;script&gt;alert(1)&lt;/script&gt;', '&lt;script&gt;alert(1)&lt;/script&gt;'],
    ['&#60;img src=x onerror=alert(1)&#62;', '&lt;img src=x onerror=alert(1)&gt;'],
    ['&amp;lt;b&amp;gt;', '&amp;lt;b&amp;gt;'],
    ['＜script＞alert(1)＜/script＞', '＜script＞alert(1)＜/script＞'],
    ['<b>a</b\n>c', '<b>a</b>c'],
    ['<b/onmouseover=alert(1)>x</b>', '<b>x</b>']
  ]
  for (const [input, expected] of cases) {
    const out = sanitizeHtml(input, POLICY)
    t.is(out, expected, JSON.stringify(input))
    t.absent(/<\s*(script|svg|iframe|object|style|math)/i.test(out), 'no dangerous tag')
    t.absent(/<[^>]*\son[a-z]+=/i.test(out), 'no event handler attribute')
    t.absent(/<[^>]*(javascript:|vbscript:|data:)/i.test(out), 'no script URL in a tag')
  }
})

test('sanitizeHtml: some things are never kept, whatever the policy', (t) => {
  t.is(sanitizeHtml('<script>alert(1)</script>x', { allowedTags: ['script'] }), 'x')
  t.is(sanitizeHtml('<svg onload=alert(1)></svg>', { allowedTags: ['svg'], allowedAttributes: { svg: ['onload'] } }), '')
  t.is(
    sanitizeHtml('<a href="https://x" style="background:url(javascript:alert(1))" onclick="y">s</a>', {
      allowedTags: ['a'],
      allowedAttributes: { a: ['href', 'style', 'onclick'] }
    }),
    '<a href="https://x">s</a>'
  )
  t.is(sanitizeHtml('<a href="//other.example/x">p</a>', { allowedTags: ['a'], allowedAttributes: { a: ['href'] }, allowProtocolRelative: false }), '<a>p</a>')
  t.is(sanitizeHtml('<a href="data:,x">p</a>', { allowedTags: ['a'], allowedAttributes: { a: ['href'] }, allowedSchemes: ['https'] }), '<a>p</a>')
  t.is(sanitizeHtml('<a href="https://x">p</a>', { allowedTags: ['a'], allowedAttributes: { '*': ['href'] } }), '<a href="https://x">p</a>', "'*' attributes")
})

test('sanitizeHtml: nesting limit', (t) => {
  const deep = '<b>'.repeat(100) + 'x' + '</b>'.repeat(100)
  const out = sanitizeHtml(deep, { allowedTags: ['b'], nestingLimit: 3 })
  t.is(out, '<b><b><b>x</b></b></b>')
})

test('escapeText', (t) => {
  t.is(escapeText('<a href="x">\'&\'</a>'), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;')
  t.is(escapeText(12), '12')
})
