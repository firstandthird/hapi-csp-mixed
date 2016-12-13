'use strict';
const Hapi = require('hapi');
const hapiCSP = require('../index.js');
const async = require('async');

const server = new Hapi.Server({ debug: { request: ['error'] } });
server.connection({ port: 8080 });

async.autoInject({
  register: (done) => {
    // first register the plugin with the hapi server:
    server.register({
      register: hapiCSP,
      options: {
        // standard responses in hapi have response.variety === 'plain'
        varietiesToInclude: ['plain'],
        fetchDirectives: {
          // we are adding a directive to report when an img tag has a src that is not a secure https
          'img-src': 'https:',
          // this directive tells the browser where to POST the error report:
          'report-uri': 'http://localhost:8080/report'
        }
      }
    }, done);
  },
  routes: (register, done) => {
    // add a route that we can use for testing.
    // when you open localhost:8080/, your browser console should show an error report:
    server.route({
      path: '/',
      method: 'GET',
      handler: (request, reply) => {
        // reply contains a mix of http/https img sources, which our header said was no bueno:
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
