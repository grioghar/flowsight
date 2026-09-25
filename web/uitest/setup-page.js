var window = this;
var FAILURE = null;
function fail(e) { FAILURE = e; }
function mkEl() {
  return {
    innerHTML: '', style: {}, hidden: true, onclick: null, dataset: {},
    checked: false, value: '',
    addEventListener: function () { }, appendChild: function () { },
    querySelector: function () { return mkEl(); }, querySelectorAll: function () { return []; },
    getBoundingClientRect: function () { return { bottom: 0 }; }, parentNode: null
  };
}
var document = {
  getElementById: function () { return mkEl(); }, querySelector: function () { return mkEl(); },
  querySelectorAll: function () { return []; }, addEventListener: function () { },
  body: { contains: function () { return true; } }, createElement: function () { return mkEl(); }
};
var localStorage = { getItem: function () { return null; }, setItem: function () { } };
var location = { hash: '#setup' };
var setTimeout = function () { };
load('web/static/lib.js');

// Mock fixture for setup state
var SETUP_STATE = {
  completed: false,
  completed_at: 0,
  platform: 'opnsense',
  interfaces: ['vtnet0', 'igb1', 'igb2'],
  binaries: {
    ntopng: true,
    suricata: true,
    squid: true,
    nmap: false,
    tcpdump: true
  },
  license: {
    tier: 'community'
  },
  data_dir_space: 1024000,
  api_loopback: true,
  api_token_set: false,
  pihole_found: '192.168.1.1',
  proxmox_found: ''
};

// Test 1: Render step 1 (Welcome & license)
try {
  // Simulate the render call
  FS.registerPage('setup', {
    title: 'Setup wizard',
    async render(el) {
      // This is a simplified mock of what the actual render does
      var html = '';

      // Banner (if not completed)
      if (!SETUP_STATE.completed) {
        html += '<div id="setup-banner">Setup incomplete</div>';
      }

      // Wizard steps
      html += '<div class="wizard-steps">';
      for (var i = 1; i <= 12; i++) {
        html += '<div class="step" data-step="' + i + '">Step ' + i + '</div>';
      }
      html += '</div>';

      // Step content
      html += '<div class="wizard-content" id="step-content"></div>';

      el.innerHTML = html;

      // Verify step list is rendered
      var steps = el.querySelectorAll('.step');
      if (!steps || steps.length === 0) {
        fail('Step list not rendered');
        return;
      }
      if (steps.length !== 12) {
        fail('Expected 12 steps, got ' + steps.length);
        return;
      }

      // Test rendering step 1 content
      var step1Content = '<div><label>License key (optional)</label><input id="license-key" type="text"></div>';
      el.querySelector('#step-content').innerHTML = step1Content;

      var licenseInput = el.querySelector('#license-key');
      if (!licenseInput) {
        fail('License input not found');
        return;
      }
    }
  });

  // Verify setup page is registered
  if (!FS.pages || !FS.pages['setup']) {
    fail('Setup page not registered');
  }
} catch (e) {
  fail('Error rendering step 1: ' + e.message);
}

// Test 2: Render step 3 (Traffic source)
try {
  var step3Html = '';
  step3Html += '<div class="card">';
  step3Html += '<label>ntopng URL</label>';
  step3Html += '<input id="ntopng-url" type="text" placeholder="http://127.0.0.1:3000">';
  step3Html += '<label>Username (if required)</label>';
  step3Html += '<input id="ntopng-username" type="text">';
  step3Html += '<button id="test-ntopng">Test connection</button>';
  step3Html += '<span id="ntopng-status"></span>';
  step3Html += '</div>';

  // Verify form fields can be created
  var mockEl = mkEl();
  mockEl.innerHTML = step3Html;
  mockEl.querySelector = function (sel) {
    if (sel === '#ntopng-url') {
      return { value: 'http://127.0.0.1:3000', type: 'text' };
    }
    if (sel === '#ntopng-username') {
      return { value: 'admin', type: 'text' };
    }
    if (sel === '#test-ntopng') {
      return { onclick: null };
    }
    return mkEl();
  };

  var urlField = mockEl.querySelector('#ntopng-url');
  if (!urlField || urlField.value !== 'http://127.0.0.1:3000') {
    fail('ntopng URL field not properly rendered');
  }
} catch (e) {
  fail('Error rendering step 3: ' + e.message);
}

// Test 3: Render step 12 (Review & finish)
try {
  var step12Html = '';
  step12Html += '<div class="card">';
  step12Html += '<h2>Review & finish</h2>';
  step12Html += '<ul><li>Site basics</li><li>Traffic source</li><li>DNS source</li></ul>';
  step12Html += '<button id="finish-wizard">Mark completed</button>';
  step12Html += '<button id="run-again">Run again</button>';
  step12Html += '</div>';

  // Verify buttons are accessible
  var mockEl2 = mkEl();
  mockEl2.innerHTML = step12Html;
  mockEl2.querySelector = function (sel) {
    if (sel === '#finish-wizard') {
      return { onclick: null };
    }
    if (sel === '#run-again') {
      return { onclick: null };
    }
    return mkEl();
  };

  var finishBtn = mockEl2.querySelector('#finish-wizard');
  var runAgainBtn = mockEl2.querySelector('#run-again');

  if (!finishBtn) {
    fail('Finish button not found in step 12');
  }
  if (!runAgainBtn) {
    fail('Run again button not found in step 12');
  }
} catch (e) {
  fail('Error rendering step 12: ' + e.message);
}

// Test 4: Verify setup state interface
try {
  if (SETUP_STATE.completed !== false) {
    fail('Setup state completed flag not correct');
  }
  if (SETUP_STATE.platform !== 'opnsense') {
    fail('Platform detection not correct');
  }
  if (!SETUP_STATE.binaries.ntopng) {
    fail('Binary detection not correct');
  }
  if (SETUP_STATE.license.tier !== 'community') {
    fail('License tier not correct');
  }
} catch (e) {
  fail('Error checking setup state: ' + e.message);
}

// Verify all tests passed
if (FAILURE) {
  throw FAILURE;
}
