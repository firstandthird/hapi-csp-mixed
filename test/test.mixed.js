'use strict';

const async = require('async');
const Hapi = require('hapi');
const code = require('code');
const lab = exports.lab = require('lab').script();
const hapiCSP = require('../index.js');

let server;
lab.beforeEach((done) => {
  server = new Hapi.Server({
  });
  server.connection({ port: 8080 });
  done();
});

lab.afterEach((done) => {
  server.stop(() => {
    done();
  });
});


lab.test('should add default headers to incoming requests of the indicated variety ', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          varietiesToInclude: ['plain']
        }
      }, done);
    },
    routes: (register, done) => {
      server.route({
        path: '/test',
        method: 'GET',
        handler: (request, reply) => {
          reply('good');
        }
      });
      done();
    },
    inject: (routes, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject, done) => {
      code.expect(inject.statusCode).to.equal(200);
      const headers = inject.headers;
      code.expect(headers).to.include('content-security-policy-report-only');
      code.expect(headers['content-security-policy-report-only']).to.equal('default-src https: \'unsafe-inline\' \'unsafe-eval\';report-uri /csp_reports');
      code.expect(headers['content-security-policy']).to.equal('upgrade-insecure-requests;');
      done();
    }
  }, allDone);
});

lab.test('should not add header if not of the indicated variety ', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          varietiesToInclude: ['view']
        }
      }, done);
    },
    routes: (register, done) => {
      server.route({
        path: '/test',
        method: 'GET',
        handler: (request, reply) => {
          reply('good');
        }
      });
      done();
    },
    inject: (routes, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject, done) => {
      code.expect(inject.statusCode).to.equal(200);
      const headers = inject.headers;
      code.expect(headers).to.not.include('content-security-policy-report-only');
      done();
    }
  }, allDone);
});

lab.test('should over-ride fetch directives and policies ', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          varietiesToInclude: ['plain'],
          fetchDirectives: {
            'font-src': 'https:',
            'report-uri': 'http://localhost:8080/csp_reports'
          }
        }
      }, done);
    },
    routes: (register, done) => {
      server.route({
        path: '/test',
        method: 'GET',
        handler: (request, reply) => {
          reply('good');
        }
      });
      done();
    },
    inject: (routes, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject, done) => {
      code.expect(inject.statusCode).to.equal(200);
      const headers = inject.headers;
      code.expect(headers).to.include('content-security-policy-report-only');
      code.expect(headers['content-security-policy-report-only']).to.include('font-src https:;report-uri http://localhost:8080/csp_reports');
      done();
    }
  }, allDone);
});

lab.test('should provide a route at route-url ', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          varietiesToInclude: ['plain'],
          fetchDirectives: {
            // this directive tells the browser where to POST the error report:
            'report-uri': 'http://localhost:8080/report'
          }
        }
      }, done);
    },
    inject: (register, done) => {
      server.inject({
        url: '/report',
        method: 'POST',
        headers: { 'content-type': 'application/csp-report' }
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject, done) => {
      code.expect(inject.statusCode).to.equal(200);
      done();
    }
  }, allDone);
});

lab.test('suppress report header if reportErrors is false ', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          reportErrors: false
        },
      }, done);
    },
    routes: (register, done) => {
      server.route({
        path: '/test',
        method: 'GET',
        handler: (request, reply) => {
          reply('good');
        }
      });
      done();
    },
    inject: (routes, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject, done) => {
      code.expect(inject.statusCode).to.equal(200);
      const headers = inject.headers;
      code.expect(headers).to.not.include('content-security-policy-report-only');
      done();
    }
  }, allDone);
});


lab.test('suppress https upgrade header if upgradeInsecureRequests is false ', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          upgradeInsecureRequests: false
        },
      }, done);
    },
    routes: (register, done) => {
      server.route({
        path: '/test',
        method: 'GET',
        handler: (request, reply) => {
          reply('good');
        }
      });
      done();
    },
    inject: (routes, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject, done) => {
      code.expect(inject.statusCode).to.equal(200);
      const headers = inject.headers;
      code.expect(headers).to.not.include('content-security-policy');
      done();
    }
  }, allDone);
});
