'use strict';
const _ = require('lodash');
const aug = require('aug');
const url = require('url');
const pluginDefaults = {
  logTags: ['content-security-policy-report'],
  varietiesToInclude: ['view'],
  fetchDirectives: {
    'default-src': ['https:'],
    'report-uri': 'http://localhost/csp_reports'
  },
  headerKey: 'Content-Security-Policy-Report-Only',
  policyHeaderKey: 'Content-Security-Policy',
  policyHeader: 'upgrade-insecure-requests;'
};

exports.register = (server, pluginOptions, next) => {
  const options = aug(pluginDefaults, pluginOptions);
  // policies are single-quoted in CSP headers, urls/etc aren't:
  const quotify = (policy) => {
    if (['none', 'self', 'unsafe-inline', 'unsafe-eval'].indexOf(policy) > -1) {
      return `'${policy}'`;
    }
    return policy;
  };

  // stringify the contents of the CSP header
  // eg: default-src https: 'unsafe-inline' 'unsafe-eval'; report-uri https://example.com/reportingEndpoint
  const cspValue = _.reduce(options.fetchDirectives, (memo, fetchDirectiveValue, fetchDirective) => {
    // policy could be either a single policy or list of them:
    if (typeof fetchDirectiveValue === 'string') {
      memo.push(`${fetchDirective} ${quotify(fetchDirectiveValue)}`);
    } else {
      memo.push(`${fetchDirective} ${_.map(fetchDirectiveValue, item => quotify(item)).join(' ')}`);
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
    if (request.response.isBoom) {
      response.output.headers[options.headerKey] = cspValue;
      response.output.headers[options.policyHeaderKey] = options.policyHeader;
    } else {
      response.header(options.headerKey, cspValue);
      response.header(options.policyHeaderKey, options.policyHeader);
    }
    reply.continue();
  });
  // will set up an endpoint at report-uri if you want:
  if (options.fetchDirectives['report-uri']) {
    const routeOptions = {
      path:  url.parse(options.fetchDirectives['report-uri']).pathname,
      method: '*',
      config: {
        payload: {
          parse: false,
          allow: ['application/csp-report']
        }
      }
    };
    routeOptions.handler = options.routeHandler ? options.routeHandler : (request, reply) => {
      // the report will be a Buffer representing a JSON string:
      server.log(options.logTags, request.payload.toString('utf-8'));
      reply();
    };
    server.route(routeOptions);
  }
  next();
};
exports.register.attributes = {
  pkg: require('./package.json')
};
