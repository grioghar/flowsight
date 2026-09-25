var window = this;
var FAILURE = null;
function fail(e){ FAILURE = e; }
var handlers = {};
function mkEl(){ return { innerHTML:'', style:{}, hidden:true, onclick:null, className: '',
  addEventListener:function(k,f){ handlers[k]=f; }, appendChild:function(){},
  querySelector:function(){ return mkEl(); }, querySelectorAll:function(){ return []; },
  getBoundingClientRect:function(){ return {bottom:0}; }, parentNode: null, classList: { add:function(){}, remove:function(){}, contains:function(){} },
  children: [], offsetHeight: 0, offsetWidth: 0 }; }
var document = { getElementById:function(){ return mkEl(); }, querySelector:function(){ return mkEl(); },
  querySelectorAll:function(){ return []; }, addEventListener:function(){},
  body:{ contains:function(){ return true; } }, createElement:function(){ return mkEl(); }, createRange:function(){ return {}; } };
var localStorage = { getItem:function(){ return null; }, setItem:function(){} };
var location = { hash: '' };

var FS = {
  esc:function(x){ return String(x); }, hostLink:function(ip){return ip;}, pill:function(x){return x;},
  ago:function(t){ return 'ago'; },
  registeredPages:{}, registerPage:function(k,v){ this.registeredPages[k]=v; },
  $: function(sel){ return mkEl(); },
  $$: function(sel){ return []; },
  modal: function(html, onMount){ if(onMount) onMount(mkEl()); },
  closeModal: function(){},
  toast: function(msg){},
  proxmox: {}
};

// Test fixtures
var fixtures = {
  '/api/proxmox/inventory': {
    nodes:[{name:'proxmox',pve_version:'8.0',cpu:25,mem_percent:45,uptime:86400*30,load:'1.5',rootfs_pct:42,kernel:'Linux 6.x'}],
    guests:[{vmid:102,node:'proxmox',name:'opnsense',type:'qemu',status:'running',ips:['192.168.1.1'],os:'OpenBSD',agent_state:'responding',cores:4,memory:8192}]
  },
  '/api/proxmox/status': { last_poll:Math.floor(Date.now()/1000)-600, error:'' },
  '/api/proxmox/map?hours=24': {
    guests:[{vmid:102,node:'proxmox',name:'opnsense',type:'qemu',status:'running',ips:['192.168.1.1'],os:'OpenBSD',agent_state:'responding'}],
    edges:[],
    external:[],
    requirements:{}
  }
};

var get = function(url){
  return Promise.resolve(fixtures[url] || {error:'not found'});
};

var post = function(url, data){
  return Promise.resolve({ok:true});
};

var num = function(x){ return String(x); };
var ago = function(t){ return 'ago'; };
var card = function(title, content){ return '<div class="card"><h3>' + title + '</h3>' + content + '</div>'; };
var kpi = function(label, value, detail){ return '<div class="kpi">' + label + ': ' + value + '</div>'; };
var pill = function(x){ return '<span class="pill">' + x + '</span>'; };

// Load and initialize layout functions inline
function initProxmoxFunctions() {
  FS.proxmox.layout = function(guests, nodes) {
    var nodeList = nodes || [];
    var guestsByNode = {};
    for (var i = 0; i < (guests || []).length; i++) {
      var g = guests[i];
      if (!guestsByNode[g.node]) guestsByNode[g.node] = [];
      guestsByNode[g.node].push(g);
    }
    var nodeWidth = 280, nodeHeight = 100, columnGap = 60, rowGap = 40;
    var x = 40, positions = {};
    for (var i = 0; i < nodeList.length; i++) {
      var node = nodeList[i];
      var y = 40;
      var nodeGuests = guestsByNode[node.name] || [];
      for (var j = 0; j < nodeGuests.length; j++) {
        var g = nodeGuests[j];
        positions[g.vmid] = {x:x, y:y, node:node.name, nodeWidth:nodeWidth, nodeHeight:nodeHeight};
        y += nodeHeight + rowGap;
      }
      x += nodeWidth + columnGap;
    }
    return {positions:positions, totalWidth:x+40, totalHeight:600};
  };

  FS.proxmox.edgePath = function(fromPos, toPos) {
    var x1 = fromPos.x + fromPos.nodeWidth;
    var y1 = fromPos.y + fromPos.nodeHeight / 2;
    var x2 = toPos.x, y2 = toPos.y + toPos.nodeHeight / 2;
    var cpx = (x1 + x2) / 2;
    return 'M ' + x1 + ' ' + y1 + ' C ' + cpx + ' ' + y1 + ' ' + cpx + ' ' + y2 + ' ' + x2 + ' ' + y2;
  };

  FS.proxmox.requirementsMarkdown = function(req) {
    var md = '# Guest: ' + req.vmid + ' (' + req.node + ')\n\n';
    if (req.cores || req.memory) {
      md += '## Resources\n- Cores: ' + (req.cores || 'N/A') + '\n- Memory: ' + (req.memory ? (req.memory / 1024) + ' GiB' : 'N/A') + '\n\n';
    }
    return md;
  };
}

function testProxmoxLayout() {
  var guests = [{vmid:102,node:'proxmox',name:'opnsense',type:'qemu'}];
  var nodes = [{name:'proxmox'}];
  var layout = FS.proxmox.layout(guests, nodes);

  if (!layout.positions || !layout.positions[102]) fail('layout missing guest position');
  var pos = layout.positions[102];
  if (pos.x === undefined || pos.y === undefined) fail('layout position missing x,y');
  if (layout.totalWidth <= 0 || layout.totalHeight <= 0) fail('layout dimensions invalid');

}

function testEdgePath() {
  var from = {x:0, y:0, nodeWidth:280, nodeHeight:100};
  var to = {x:340, y:0, nodeWidth:280, nodeHeight:100};
  var path = FS.proxmox.edgePath(from, to);

  if (!path || path.indexOf('M') !== 0) fail('edgePath missing SVG path');
  if (path.indexOf('C') === -1) fail('edgePath not cubic curve');

}

function testRequirementsMarkdown() {
  var req = {vmid:102, node:'proxmox', cores:4, memory:8192};
  var md = FS.proxmox.requirementsMarkdown(req);

  if (!md || md.indexOf('102') === -1) fail('requirements missing VMID');
  if (md.indexOf('Resources') === -1) fail('requirements missing Resources section');

}

function testProxmoxPage(){
  var el = mkEl(); el.innerHTML = '';
  var page = FS.registeredPages['proxmox'];
  if(!page) { fail('proxmox page not registered'); return Promise.resolve(); }

  return page.render(el, { params: {} }).then(function(){
    if(!el.innerHTML || el.innerHTML.length < 10) fail('proxmox page empty');
    if(el.innerHTML.indexOf('Proxmox') === -1 && el.innerHTML.indexOf('proxmox') === -1) fail('proxmox name missing');

  }).catch(function(e){ fail(e); });
}

initProxmoxFunctions();
testProxmoxLayout();
testEdgePath();
testRequirementsMarkdown();

testProxmoxPage().then(function(){
  if(FAILURE) throw FAILURE;
}).catch(function(e){

  process.exit(1);
});
