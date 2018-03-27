const Hapi = require('hapi');
const code = require('code');
const lab = exports.lab = require('lab').script();
const hapiCSP = require('../index.js');

let server;

lab.beforeEach(() => {
  server = new Hapi.Server({ port: 8080 });
});

lab.afterEach(async() => {
  await server.stop();
});

lab.test('should add default headers to incoming requests of the indicated variety ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      varietiesToInclude: ['plain']
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, h) => 'good'
  });
  const injectResponse = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(injectResponse.statusCode).to.equal(200);
  const headers = injectResponse.headers;
  code.expect(headers).to.include('content-security-policy-report-only');
  code.expect(headers['content-security-policy-report-only']).to.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers['content-security-policy']).to.equal('upgrade-insecure-requests;');
});

lab.test('should not add header if not of the indicated variety ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      varietiesToInclude: ['view']
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, h) => 'good'
  });
  const injectResponse = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(injectResponse.statusCode).to.equal(200);
  const headers = injectResponse.headers;
  code.expect(headers).to.not.include('content-security-policy-report-only');
});

lab.test('will still add header if specified by the route config ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      varietiesToInclude: ['view']
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    config: {
      plugins: {
        'hapi-csp-mixed': {
          cspHeaders: true // setting this to true forces CSP headers on
        }
      }
    },
    // does not use 'view' but does have the cspHeaders option:
    handler: (request, h) => 'good'
  });
  const injectResponse = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(injectResponse.statusCode).to.equal(200);
  const headers = injectResponse.headers;
  code.expect(headers).to.include('content-security-policy-report-only');
  code.expect(headers['content-security-policy-report-only']).to.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers['content-security-policy']).to.equal('upgrade-insecure-requests;');
});

lab.test('should over-ride fetch directives and policies ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      varietiesToInclude: ['plain'],
      fetchDirectives: {
        'font-src': 'https:',
        'report-uri': 'http://localhost:8080/csp_reports'
      }
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, reply) => 'good'
  });
  const injectResponse = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(injectResponse.statusCode).to.equal(200);
  const headers = injectResponse.headers;
  code.expect(headers).to.include('content-security-policy-report-only');
  code.expect(headers['content-security-policy-report-only']).to.include('report-uri http://localhost:8080/csp_reports;font-src https:');
});

lab.test('will not log a fetch directive if it is an empty array', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      varietiesToInclude: ['plain'],
      fetchDirectives: {
        'font-src': []
      }
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, reply) => 'good'
  });
  const inject = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(inject.statusCode).to.equal(200);
  const headers = inject.headers;
  code.expect(headers).to.include('content-security-policy-report-only');
  // font-src won't be added since it is an array with zero entries:
  code.expect(headers['content-security-policy-report-only']).to.not.include('font-src');
});

lab.test('should provide a route at route-url ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      varietiesToInclude: ['plain'],
      fetchDirectives: {
        // this directive tells the browser where to POST the error report:
        'report-uri': 'http://localhost:8080/report'
      }
    }
  });
  const inject = await server.inject({
    url: '/report',
    method: 'POST',
    headers: { 'content-type': 'application/csp-report' },
    payload: {
      success: 'true'
    }
  });
  code.expect(inject.statusCode).to.equal(200);
});

lab.test('suppress report header if reportErrors is false ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      reportErrors: false
    },
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, h) => 'good'
  });
  const inject = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(inject.statusCode).to.equal(200);
  const headers = inject.headers;
  code.expect(headers).to.not.include('content-security-policy-report-only');
});

lab.test('suppress https upgrade header if upgradeInsecureRequests is false ', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      upgradeInsecureRequests: false
    },
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, h) => 'good'
  });
  const inject = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(inject.statusCode).to.equal(200);
  const headers = inject.headers;
  code.expect(headers).to.not.include('content-security-policy');
});

lab.test('httpsOnly option will prevent non-http requests', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      httpsOnly: true,
      varietiesToInclude: ['plain']
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, h) => 'good'
  });
  server.info.protocol = 'https';
  const inject1 = await server.inject({
    url: '/test',
    method: 'GET',
  });
  server.info.protocol = 'http';
  const inject2 = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(inject1.statusCode).to.equal(200);
  const headers1 = inject1.headers;
  code.expect(headers1).to.include('content-security-policy-report-only');
  code.expect(headers1['content-security-policy-report-only']).to.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers1['content-security-policy']).to.equal('upgrade-insecure-requests;');
  code.expect(inject2.statusCode).to.equal(200);
  const headers2 = inject2.headers;
  code.expect(headers2).to.not.include('content-security-policy-report-only');
  code.expect(headers2['content-security-policy-report-only']).to.not.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers2['content-security-policy']).to.not.equal('upgrade-insecure-requests;');
});

lab.test('httpsOnly option will recognize proxy requests that are https', async() => {
  await server.register({
    plugin: hapiCSP,
    options: {
      httpsOnly: true,
      varietiesToInclude: ['plain']
    }
  });
  server.route({
    path: '/test',
    method: 'GET',
    handler: (request, h) => 'good'
  });
  const inject1 = await server.inject({
    url: '/test',
    method: 'GET',
    headers: {
      'x-forwarded-proto': 'https'
    }
  });
  const inject2 = await server.inject({
    url: '/test',
    method: 'GET',
    headers: {
      'x-forwarded-proto': 'http'
    }
  });
  const inject3 = await server.inject({
    url: '/test',
    method: 'GET',
  });
  code.expect(inject1.statusCode).to.equal(200);
  const headers1 = inject1.headers;
  code.expect(headers1).to.include('content-security-policy-report-only');
  code.expect(headers1['content-security-policy-report-only']).to.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers1['content-security-policy']).to.equal('upgrade-insecure-requests;');

  code.expect(inject2.statusCode).to.equal(200);
  const headers2 = inject2.headers;
  code.expect(headers2).to.not.include('content-security-policy-report-only');
  code.expect(headers2['content-security-policy-report-only']).to.not.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers2['content-security-policy']).to.not.equal('upgrade-insecure-requests;');

  code.expect(inject3.statusCode).to.equal(200);
  const headers3 = inject3.headers;
  code.expect(headers3).to.not.include('content-security-policy-report-only');
  code.expect(headers3['content-security-policy-report-only']).to.not.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
  code.expect(headers3['content-security-policy']).to.not.equal('upgrade-insecure-requests;');
});
