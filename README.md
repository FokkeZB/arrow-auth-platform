# Arrow Platform Authentication Plugin

> **NOTE:** This plugin will *only* work for Arrow apps served via a direct secure subdomain on the same level as the Platform dashboard.

Arrow authentication plugin that authenticates visitors to Arrow Web routes using their Appcelerator Platform session. It redirects to the SSO when the visitor requires authentication.

## Install
This plugin is distributed via NPM thanks to [app-npm](http://npmjs.com/package/appc-npm), so just do:

```
npm install arrow-auth-platform --save
```

## Configure
In your `conf/default.js` set the following:

```
  APIKeyAuthType: 'plugin',
  APIKeyAuthPlugin: 'lib/auth-platform.js',
```