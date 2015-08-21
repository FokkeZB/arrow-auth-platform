/**
 * Arrow authentication plugin that authenticates visitors to Arrow Web routes
 * using their Appcelerator Platform session. It redirects to the SSO when the
 * visitor requires authentication.
 *
 * In your conf/default.js set the following:
 * 
 * APIKeyAuthType: 'plugin',
 * APIKeyAuthPlugin: 'lib/auth-platform.js',
 */

var path = require('path');

var deasync = require('deasync');

var AppC = require(path.join('arrow', 'node_modules', 'arrow-admin', 'node_modules', 'appc-platform-sdk'));

/**
 * Authentication plugin
 * @param {Object} server Arrow instance
 */
function Plugin(server) {
	this.config = server.config;

	// exclude admin, apiDoc and api
	this.REGEXP_EXCLUDE = new RegExp('^(' + server.config.admin.prefix + '|' + server.config.admin.apiDocPrefix + '|' + server.config.apiPrefix + ')');

	var Fallback = require(path.join('arrow', 'lib', 'authentication', 'headerauthbasic'));
	this.fallback = new Fallback(server);
}

/**
 * Returns true if the plugin can validate the request.
 * @param  {Object}  req        Request
 * @param  {Boolean} noFallback Don't check the fallback (used internally)
 * @return {Boolean}            True if it can validate the request.
 */
Plugin.prototype.matchURL = function (req, noFallback) {

	// URL is not excluded
	if (!this.REGEXP_EXCLUDE.test(req.originalUrl)) {
		return true;
	}

	// matches our fallback (if allowed)
	if (!noFallback && this.fallback.matchURL(req)) {
		return true;
	}

	return false;
};

/**
 * Validate the request.
 * @param  {Object} req  Request
 * @param  {Object} resp Response
 * @return {Boolean}     True if the request was validated
 */
Plugin.prototype.validateRequest = function (req, resp) {

	// it's us that match and not (just) our fallback
	if (this.matchURL(req, true)) {
		var sid = req.cookies && (req.cookies['connect.sid'] || req.cookies['dashboard.sid']);

		// remote SID unchanged
		if (sid && req.session.sid === sid) {

			// will exist when SID was valid
			return !!req.session.user;
		}

		req.session.sid = sid || null;
		req.session.user = null;

		if (sid) {

			// we need it sync
			var validateSession = deasync(AppC.Auth.validateSession);

			try {
				var user = validateSession(sid);

				// user not in list of valid orgs or users
				if ((req.server.config.admin.validOrgs && req.server.config.admin.validOrgs.indexOf(user.org_id) === -1) || (req.server.config.admin.validEmails && req.server.config.admin.validEmails.indexOf(user.username) === -1)) {

					// simply fail because redirect will result in a loop
					return false;
				}

				req.session.user = user;

				return true;

			} catch (e) {}
		}

		// simply fail for XHR requests
		if (req.xhr) {
			return false;
		}

		// always https or we'll loop
		var currentUrl = 'https://' + req.get('host') + req.originalUrl;

		var loginUrl = AppC.baseurl + '/?redirect=' + encodeURIComponent(currentUrl);

		// or redirect for SSO
		return resp.redirect(loginUrl);
	}

	// leave it up to the fallback
	return this.fallback.validateRequest(req, resp);
};

/**
 * Prepare for test
 * @param  {Object} opts Options to modify for testing
 */
Plugin.prototype.applyCredentialsForTest = function (opts) {

	// Let our fallback do so as well
	this.fallback.applyCredentialsForTest(opts);
};

module.exports = Plugin;
