'use strict';
const aug = require('aug');
const url = require('url');
const pluginDefaults = {
  logTags: ['content-security-policy-report'],
  varietiesToInclude: ['view'],
  fetchDirectives: {
    'default-src': ['https:', 'unsafe-inline', 'unsafe-eval'],
    'report-uri': '/csp_reports'
  },
  // by default the browser will POST any error reports to report-uri, set this to false to skip that:
  reportErrors: true,
  // by default the browser will turn http requests into https requests, set this to false to prevent that:
  upgradeInsecureRequests: true
};

const policyHeaderKey = 'Content-Security-Policy';
const policyHeader = 'upgrade-insecure-requests;';
const headerKey = 'Content-Security-Policy-Report-Only';

exports.register = (server, pluginOptions, next) => {
  const options = aug('defaults', pluginDefaults, pluginOptions);
  // policies are single-quoted in CSP headers, urls/etc aren't:
  const quotify = (policy) => {
    if (['none', 'self', 'unsafe-inline', 'unsafe-eval'].indexOf(policy) > -1) {
      return `'${policy}'`;
    }
    return policy;
  };

  // stringify the contents of the CSP header
  // eg: default-src https: 'unsafe-inline' 'unsafe-eval'; report-uri https://example.com/reportingEndpoint
  const cspValue = Object.keys(options.fetchDirectives).reduce((memo, fetchDirective) => {
    const fetchDirectiveValue = options.fetchDirectives[fetchDirective];
    // policy could be either a single policy or list of them:
    if (typeof fetchDirectiveValue === 'string') {
      memo.push(`${fetchDirective} ${quotify(fetchDirectiveValue)}`);
    } else {
      memo.push(`${fetchDirective} ${fetchDirectiveValue.map(item => quotify(item)).join(' ')}`);
    }
    return memo;
  }, []).join(';');

  // calculates and adds the CSP header for each request before it returns
  server.ext('onPreResponse', (request, reply) => {
    // don't worry about it if this was called by the CSP report route:
    if (options.fetchDirectives['report-uri'] === request.path) {
      return reply.continue();
    }
    // don't worry about it if this response variety isn't in the indicated varieties:
    if (options.varietiesToInclude.indexOf(request.response.variety) < 0) {
      return reply.continue();
    }
    const response = request.response;
    if (request.response.isBoom && options.reportErrors) {
      response.output.headers[headerKey] = cspValue;
      if (options.upgradeInsecureRequests) {
        response.output.headers[policyHeaderKey] = policyHeader;
      }
    } else {
      if (options.reportErrors) {
        response.header(headerKey, cspValue);
      }
      if (options.upgradeInsecureRequests) {
        response.header(policyHeaderKey, policyHeader);
      }
    }
    reply.continue();
  });
  // will set up an endpoint at report-uri if you want:
  if (options.fetchDirectives['report-uri']) {
    const routeOptions = {
      path: url.parse(options.fetchDirectives['report-uri']).pathname,
      method: '*',
      config: {
        payload: {
          parse: false,
          allow: ['application/csp-report', 'text/html', 'application/json']
        }
      }
    };
    routeOptions.handler = options.routeHandler ? options.routeHandler : (request, reply) => {
      // the report will be a Buffer representing a JSON string:
      if (request.payload) {
        server.log(options.logTags, request.payload.toString('utf-8'));
      }
      reply();
    };
    server.route(routeOptions);
  }
  next();
};
exports.register.attributes = {
  pkg: require('./package.json')
};
