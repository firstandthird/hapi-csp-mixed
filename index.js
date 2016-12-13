const _ = require('lodash');
const aug = require('aug');

const pluginDefaults = {
  varietiesToInclude: ['view'],
  fetchDirectives: {
    'default-src': ['https:'],
    'report-uri': 'http://localhost/csp_reports'
  },
  headerKey: 'Content-Security-Policy-Report-Only'
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
    // only worry about it if this response variety is in the indicated list:
    if (options.varietiesToInclude.indexOf(request.response.variety) < 0) {
      return reply.continue();
    }
    const response = request.response;
    if (request.response.isBoom) {
      response.output.headers[options.headerKey] = cspValue;
    } else {
      response.header(options.headerKey, cspValue);
    }
    reply.continue();
  });
  // will set up an endpoint at report-uri if you want:
  if (options['report-uri']) {
    const routeOptions = {
      uri: options['report-uri'],
      method: 'POST'
    };
    // will need to try this out in browser:
    routeOptions.handler = options.routeHandler ? options.routeHandler : (request, reply) => {
      server.log(['content-security-policy-report'], request.payload);
      reply();
    };
    server.route(routeOptions);
  }
  next();
};
exports.register.attributes = {
  pkg: require('./package.json')
};
