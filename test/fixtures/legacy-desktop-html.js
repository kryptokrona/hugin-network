'use strict'

// hugin-desktop src/backend/utils.cjs:2-18, verbatim (`require('sanitize-html')`, a Node-only
// devDependency here). Returns null when sanitize-html cannot be loaded (Bare).

function load() {
	let _sanitize;
	try {
		_sanitize = require('sanitize-html');
	} catch {
		return null;
	}

	const sanitizeHtml = (input) => {
		if (typeof input !== 'string') return input;
		const clean = _sanitize(input, {
			allowedTags: [],
			allowedAttributes: {},
		});
		return clean
			.replace(/&amp;/g, '&')
			.replace(/&gt;/g, '>')
			.replace(/&lt;/g, '<')
			.replace(/&quot;/g, '"')
			.replace(/&#x27;/g, "'")
			.replace(/&#x2F;/g, '/');
	};
	return sanitizeHtml;
}

module.exports = { load };
