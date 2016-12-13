const Hapi = require('hapi');
const hapiCSP = require('../index.js');
const async = require('async');

const server = new Hapi.Server({ debug: { request: ['error'] } });
server.connection({ port: 8080 });

async.autoInject({
  register: (done) => {
    server.register({
      register: hapiCSP,
      options: {
        varietiesToInclude: ['plain'],
        fetchDirectives: {
          'img-src': 'https:',
          'report-uri': 'http://localhost:8080/report'
        }
      }
    }, done);
  },
  routes: (register, done) => {
    server.route({
      path: '/',
      method: 'GET',
      handler: (request, reply) => {
        // mixed http/https img source will trigger a browser report in most modern browsers:
        reply(`
          <img src='http://localhost:8080/a.jpg'>
          <img src='https://localhost:8080/b.jpg>
        `);
      }
    });
    done();
  },
  start: (routes, done) => {
    server.start(done);
  }
}, (err) => {
  if (err) {
    throw err;
  }
  console.log('Server started, browser to localhost:8080 to see a sample report');
});
