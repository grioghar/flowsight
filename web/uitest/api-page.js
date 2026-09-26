var window = this;
var FAILURE = null;
function fail(e){ FAILURE = e; }
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, dataset:{},
  addEventListener:function(){}, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode:null }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash:'#api' };
var setTimeout = function(){};
load('web/static/lib.js');

// Mock OpenAPI response with all CRUD operations organized by area, including rich documentation
var OPENAPI = {
  info: {
    version: '0.9.8',
    description: 'FlowSight API documentation'
  },
  paths: {
    '/api/policy/groups': {
      get: {
        tags: ['Protect', 'Policies'],
        summary: 'List all policy groups',
        operationId: 'apiGetGroups',
        parameters: [
          {name: 'limit', in: 'query', type: 'integer', required: false, description: 'Max results', schema: {type: 'integer', example: 100}},
          {name: 'offset', in: 'query', type: 'integer', required: false, description: 'Offset for pagination', schema: {type: 'integer', example: 0}}
        ],
        responses: {
          '200': {
            description: 'List of policy groups',
            content: {
              'application/json': {
                example: {groups: [{id: '1', name: 'Default', rules: 5}]}
              }
            }
          }
        }
      },
      post: {
        tags: ['Protect', 'Policies'],
        summary: 'Create a new policy group',
        operationId: 'apiCreateGroup',
        'x-write': true,
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: {type: 'string', description: 'Group name', example: 'My Group'},
                  description: {type: 'string', description: 'Group description', example: 'Test group'}
                },
                required: ['name']
              },
              example: {name: 'My Group', description: 'Test'}
            }
          }
        },
        responses: {
          '200': {
            description: 'Created policy group',
            content: {
              'application/json': {
                example: {id: '1', name: 'My Group'}
              }
            }
          }
        }
      }
    },
    '/api/policy/groups/{name}': {
      get: {
        tags: ['Protect', 'Policies'],
        summary: 'Get a specific policy group',
        operationId: 'apiGetGroup',
        parameters: [
          {name: 'name', in: 'path', required: true, description: 'Group name', schema: {type: 'string', example: 'Default'}}
        ]
      },
      put: {
        tags: ['Protect', 'Policies'],
        summary: 'Update a policy group',
        operationId: 'apiUpdateGroup',
        'x-write': true
      },
      delete: {
        tags: ['Protect', 'Policies'],
        summary: 'Delete a policy group',
        operationId: 'apiDeleteGroup',
        'x-write': true
      }
    },
    '/api/enroll/zones/{id}': {
      get: {
        tags: ['Inventory', 'Devices'],
        summary: 'Get a specific zone',
        operationId: 'apiGetZoneByID'
      },
      put: {
        tags: ['Inventory', 'Devices'],
        summary: 'Update a zone',
        operationId: 'apiUpdateZoneByID',
        'x-write': true
      },
      delete: {
        tags: ['Inventory', 'Devices'],
        summary: 'Delete a zone',
        operationId: 'apiDeleteZoneByID',
        'x-write': true
      }
    },
    '/api/alerting/channels': {
      get: {
        tags: ['Administration', 'Alerts'],
        summary: 'List all notification channels',
        operationId: 'apiGetChannels',
        responses: {
          '200': {
            description: 'List of notification channels',
            content: {
              'application/json': {
                example: {channels: [{id: 'ch-1', type: 'slack', name: 'alerts', enabled: true}]}
              }
            }
          }
        }
      }
    },
    '/api/alerting/channels/{id}': {
      delete: {
        tags: ['Administration', 'Alerts'],
        summary: 'Delete a notification channel',
        operationId: 'apiDeleteChannel',
        'x-write': true
      }
    },
    '/api/qos/rules': {
      get: {
        tags: ['Protect', 'Priority'],
        summary: 'List all traffic shaping rules',
        operationId: 'apiGetRules'
      },
      post: {
        tags: ['Protect', 'Priority'],
        summary: 'Create a new traffic shaping rule',
        operationId: 'apiCreateRule',
        'x-write': true
      }
    },
    '/api/qos/rules/{id}': {
      delete: {
        tags: ['Protect', 'Priority'],
        summary: 'Delete a traffic shaping rule',
        operationId: 'apiDeleteRule',
        'x-write': true
      }
    }
  },
  'x-tagGroups': [
    { name: 'Monitor', tags: ['Monitor/Overview'] },
    { name: 'Inventory', tags: ['Inventory/Devices'] },
    { name: 'Protect', tags: ['Protect/Policies', 'Protect/Priority'] },
    { name: 'Administration', tags: ['Administration/Alerts'] }
  ]
};

FS.get = function(p){
  if (p.indexOf('/api/openapi.json') === 0) return Promise.resolve(OPENAPI);
  return Promise.resolve({});
};

load('web/static/api.js');

if (!FS.pages.api || !FS.pages.api.render) {
  throw new Error('API page not loaded properly');
}

var el = mkEl();
FS.pages.api.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;

  // Assert operations are rendered (GET /api/policy/groups)
  if (h.indexOf('GET') < 0) throw new Error('missing GET method');
  if (h.indexOf('/api/policy/groups') < 0) throw new Error('missing /api/policy/groups path');
  if (h.indexOf('List all policy groups') < 0) throw new Error('missing operation summary');

  // Assert write operations are marked
  if (h.indexOf('bad') < 0) throw new Error('write operations not marked with badge');

  // Assert parameter documentation
  if (h.indexOf('limit') < 0) throw new Error('limit parameter not documented');
  if (h.indexOf('Max results') < 0) throw new Error('parameter description missing');

  // Assert request body fields are rendered
  if (h.indexOf('Request body') < 0) throw new Error('request body documentation missing');

  // Assert response examples are shown
  if (h.indexOf('Response example') < 0) throw new Error('response example documentation missing');

  // Assert curl button exists (actual curl generation happens on click)
  if (h.indexOf('Copy as curl') < 0) throw new Error('curl button missing');

  print('API page renders rich documentation with parameters, request bodies, and response examples');
}).catch(fail);

if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
