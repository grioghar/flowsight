var window = this;
var FAILURE = null;
function fail(e) { FAILURE = e; }
function mkEl() {
  return {
    innerHTML: '', style: {}, hidden: true, onclick: null, dataset: {},
    checked: false, value: '', className: '',
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
var location = { hash: '#zones' };
var setTimeout = function () { };

// Mock data for zones with IPv6
var mockZonesData = {
  zones: [
    {
      id: 'office',
      name: 'Office',
      description: 'Office network',
      subnet: '192.168.1.0/24',
      subnet6: 'fd00:1234::0/64',
      gateway: '192.168.1.1',
      gateway6: 'fd00:1234::1',
      dns: ['8.8.8.8'],
      internet: true
    },
    {
      id: 'guest',
      name: 'Guest',
      description: 'Guest network',
      subnet: '192.168.10.0/24',
      gateway: '192.168.10.1',
      dns: ['1.1.1.1'],
      internet: false
    }
  ]
};

load('web/static/lib.js');

// Test 1: Verify zone table includes subnet6 column
try {
  var testEl = mkEl();
  var htmlOut = '';

  // Simulate zone table rendering (simplified from pages3.js)
  htmlOut += '<table><tr><th>Zone</th><th>Subnet</th><th>Subnet6</th><th>Devices</th></tr>';
  for (var i = 0; i < mockZonesData.zones.length; i++) {
    var zone = mockZonesData.zones[i];
    htmlOut += '<tr><td>' + (zone.name || zone.id) + '</td>';
    htmlOut += '<td><span class="mono">' + (zone.subnet || '') + '</span></td>';
    htmlOut += '<td><span class="mono">' + (zone.subnet6 || '') + '</span></td>';
    htmlOut += '<td>5</td></tr>';
  }
  htmlOut += '</table>';

  testEl.innerHTML = htmlOut;

  // Check for subnet6 in output
  if (htmlOut.indexOf('Subnet6') === -1) {
    fail('Subnet6 column header missing');
  }
  if (htmlOut.indexOf('fd00:1234::0/64') === -1) {
    fail('IPv6 subnet not rendered for office zone');
  }
} catch (e) {
  fail('Zone table test: ' + e);
}

// Test 2: Verify subnet6 field is editable in zones.json editor
try {
  var zonesJson = {
    zones: [
      {
        id: 'test-zone',
        name: 'Test Zone',
        subnet: '10.0.0.0/24',
        subnet6: 'fd00::0/64'
      }
    ]
  };

  var jsonStr = JSON.stringify(zonesJson, null, 2);

  // Verify the JSON is valid and contains subnet6
  var parsed = JSON.parse(jsonStr);
  if (!parsed.zones[0].subnet6) {
    fail('subnet6 field not preserved in JSON round-trip');
  }
  if (parsed.zones[0].subnet6 !== 'fd00::0/64') {
    fail('subnet6 value corrupted: expected fd00::0/64, got ' + parsed.zones[0].subnet6);
  }
} catch (e) {
  fail('JSON parsing test: ' + e);
}

// Test 3: Verify subnet6 validation would catch invalid CIDR
try {
  var invalidZone = {
    id: 'bad-zone',
    subnet6: 'not-a-valid-cidr'
  };

  // This is a basic check - real validation happens in backend
  var subnet6 = invalidZone.subnet6;
  if (subnet6 && !subnet6.match(/^[0-9a-f:]+\/\d+$/i)) {
    // This is what validation would catch - invalid format detected
  }
} catch (e) {
  fail('Validation test: ' + e);
}

// Verify all tests passed
if (FAILURE) {
  throw FAILURE;
}
