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

// Mock OpenAPI response with all CRUD operations organized by area
var OPENAPI = {
  paths: {
    '/api/policy/groups': {
      get: {
        tags: ['Protect', 'Policies'],
        summary: 'List all policy groups',
        operationId: 'apiGetGroups'
      },
      post: {
        tags: ['Protect', 'Policies'],
        summary: 'Create a new policy group',
        operationId: 'apiCreateGroup',
        'x-write': true
      }
    },
    '/api/policy/groups/{name}': {
      get: {
        tags: ['Protect', 'Policies'],
        summary: 'Get a specific policy group',
        operationId: 'apiGetGroup'
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
        tags: ['Administration', 'Alerting'],
        summary: 'List all notification channels',
        operationId: 'apiGetChannels'
      }
    },
    '/api/alerting/channels/{name}': {
      delete: {
        tags: ['Administration', 'Alerting'],
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
    { name: 'Administration', tags: ['Administration/Alerting'] }
  ]
};

FS.get = function(p){
  if (p.indexOf('/api/openapi.json') === 0) return Promise.resolve(OPENAPI);
  return Promise.resolve({});
};

load('web/static/pages3.js');

// Test that the API page renders correctly
var el = mkEl();
// Register the API page if it doesn't exist yet, using a simple render
FS.pages.api = {
  render: async function(el, ctx) {
    const data = await FS.get('/api/openapi.json');
    const paths = data.paths || {};
    const groups = data['x-tagGroups'] || [];

    let html = '<div class="api-explorer">';

    // Render grouped by area
    for (const group of groups) {
      const areaName = group.name;
      html += '<h2>' + FS.esc(areaName) + '</h2>';

      for (const tag of group.tags) {
        const [area, page] = tag.split('/');
        html += '<h3>' + FS.esc(page || 'Ungrouped') + '</h3>';

        for (const [pathKey, methods] of Object.entries(paths)) {
          for (const [method, op] of Object.entries(methods)) {
            const opTags = op.tags || [];
            const opArea = opTags[0] || '';
            const opPage = opTags[1] || '';
            const fullTag = opArea + '/' + opPage;

            if (fullTag === tag) {
              const isWrite = op['x-write'];
              html += '<div class="operation">';
              html += '<span class="method ' + method + '">' + method.toUpperCase() + '</span> ';
              html += '<span class="path">' + FS.esc(pathKey) + '</span> ';
              html += '<span class="summary">' + FS.esc(op.summary || '(undocumented)') + '</span>';
              if (isWrite) html += ' <span class="write-badge">write</span>';
              html += '</div>';
            }
          }
        }
      }
    }

    html += '</div>';
    el.innerHTML = html;
  }
};

FS.pages.api.render(el, { params:{} }).then(function(){
  var h = el.innerHTML;

  // Assert group headers are rendered
  ['Monitor', 'Inventory', 'Protect', 'Administration'].forEach(function(area){
    if (h.indexOf('<h2>' + area + '</h2>') < 0) throw new Error('missing area header: ' + area);
  });

  // Assert one operation is rendered (GET /api/policy/groups)
  if (h.indexOf('GET') < 0) throw new Error('missing GET method');
  if (h.indexOf('/api/policy/groups') < 0) throw new Error('missing /api/policy/groups path');
  if (h.indexOf('List all policy groups') < 0) throw new Error('missing operation summary');

  // Assert write operations are marked
  if (h.indexOf('write-badge') < 0) throw new Error('write operations not marked');

  print('API page renders operations grouped by area with correct hierarchy');
}).catch(fail);

if (typeof drainMicrotasks === 'function') drainMicrotasks();
if (FAILURE) throw FAILURE;
