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

lab.test('will still add header if specified by the route config ', (allDone) => {
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
        config: {
          plugins: {
            'hapi-csp-mixed': {
              cspHeaders: true // setting this to true forces CSP headers on
            }
          }
        },
        handler: (request, reply) => {
          // does not use 'view' but does have the cspHeaders option:
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
      code.expect(headers['content-security-policy-report-only']).to.include('report-uri http://localhost:8080/csp_reports;font-src https:');
      done();
    }
  }, allDone);
});

lab.test('will not log a fetch directive if it is an empty array', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          varietiesToInclude: ['plain'],
          fetchDirectives: {
            'font-src': []
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
      // font-src won't be added since it is an array with zero entries:
      code.expect(headers['content-security-policy-report-only']).to.not.include('font-src');
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
        headers: { 'content-type': 'application/csp-report' },
        payload: {
          success: 'true'
        }
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

lab.test('httpsOnly option will prevent non-http requests', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          httpsOnly: true,
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
    inject1: (routes, done) => {
      server.info.protocol = 'https';
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    inject2: (inject1, done) => {
      server.info.protocol = 'http';
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    verify: (inject1, inject2, done) => {
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

      done();
    }
  }, allDone);
});

lab.test('httpsOnly option will recognize proxy requests that are https', (allDone) => {
  async.autoInject({
    register: (done) => {
      server.register({
        register: hapiCSP,
        options: {
          httpsOnly: true,
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
    inject1: (routes, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
        headers: {
          'x-forwarded-proto': 'https'
        }
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    inject2: (inject1, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
        headers: {
          'x-forwarded-proto': 'http'
        }
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },
    inject3: (inject2, done) => {
      server.inject({
        url: '/test',
        method: 'GET',
      }, (injectResponse) => {
        done(null, injectResponse);
      });
    },

    verify: (inject1, inject2, inject3, done) => {
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

      done();
    }
  }, allDone);
});
