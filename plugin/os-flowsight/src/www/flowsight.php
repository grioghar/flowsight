<?php

/*
 * FlowSight inside the OPNsense web GUI.
 *
 * flowsightd binds to loopback and ships no authentication of its own; the
 * GUI has already authenticated the user, so this page is the only door:
 *
 *   flowsight.php            the page, inside the OPNsense chrome
 *   flowsight.php?app=1      the FlowSight application shell (in an iframe)
 *   flowsight.php?asset=…    static files of the shell
 *   flowsight.php?api=/api/… JSON API, GET and POST
 *
 * Writes are accepted only with the session's CSRF token in the X-CSRFToken
 * header and an Origin (or Referer) matching this host. The GUI user's name
 * travels to the daemon in X-Flowsight-User so the audit log names people,
 * not "local".
 */

require_once("guiconfig.inc");

$FLOWSIGHT_BASE = "http://127.0.0.1:8080";

function fs_fetch($url, $method = "GET", $body = null, $headers = [])
{
    $ch = curl_init($url);
    $hdrs = array_merge(["X-Requested-With: Flowsight"], $headers);
    if (!empty($_SESSION["Username"])) {
        $hdrs[] = "X-Flowsight-User: " . preg_replace('/[^A-Za-z0-9@._-]/', '', $_SESSION["Username"]);
    }
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_HEADER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $hdrs,
    ]);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($resp === false) {
        return [null, 0, [], $err];
    }
    $rawh = substr($resp, 0, $hsize);
    $out = substr($resp, $hsize);
    $rh = [];
    foreach (explode("\r\n", $rawh) as $line) {
        if (strpos($line, ":") !== false) {
            list($k, $v) = explode(":", $line, 2);
            $rh[strtolower(trim($k))] = trim($v);
        }
    }
    return [$out, $code, $rh, $err];
}

function fs_same_origin()
{
    $host = $_SERVER["HTTP_HOST"] ?? "";
    foreach (["HTTP_ORIGIN", "HTTP_REFERER"] as $h) {
        if (!empty($_SERVER[$h])) {
            $u = parse_url($_SERVER[$h]);
            $ohost = ($u["host"] ?? "") . (isset($u["port"]) ? ":" . $u["port"] : "");
            $hostOnly = explode(":", $host)[0];
            return $ohost === $host || ($u["host"] ?? "") === $hostOnly;
        }
    }
    return false;
}

function fs_fail($code, $msg)
{
    http_response_code($code);
    header("Content-Type: application/json");
    echo json_encode(["error" => $msg]);
    exit;
}

/* ---------------------------------------------------------------- API */
if (isset($_GET["api"])) {
    $path = (string)$_GET["api"];
    if (strpos($path, "/api/") !== 0 || strpos($path, "..") !== false || preg_match('/[\r\n\s]/', $path)) {
        fs_fail(400, "bad api path");
    }
    $method = $_SERVER["REQUEST_METHOD"];
    $body = null;
    if ($method === "POST") {
        if (!fs_same_origin()) {
            fs_fail(403, "cross-origin write refused");
        }
        /* guiconfig.inc already rejected a POST without a valid X-CSRFToken
           header (LegacyCSRF); check again so this file does not depend on
           that behaviour staying put. */
        if (empty($_SERVER["HTTP_X_CSRFTOKEN"]) || !(new LegacyCSRF())->checkToken()) {
            fs_fail(403, "invalid CSRF token");
        }
        $body = file_get_contents("php://input");
        if (strlen($body) > 4 * 1024 * 1024) {
            fs_fail(413, "payload too large");
        }
    } elseif ($method !== "GET") {
        fs_fail(405, "method not allowed");
    }
    list($out, $code, $rh, $err) = fs_fetch($FLOWSIGHT_BASE . $path, $method, $body,
        $body !== null ? ["Content-Type: application/json"] : []);
    if ($out === null) {
        fs_fail(502, "flowsightd unreachable: " . $err);
    }
    http_response_code($code ?: 200);
    header("Content-Type: " . ($rh["content-type"] ?? "application/json"));
    if (!empty($rh["content-disposition"])) {
        header("Content-Disposition: " . $rh["content-disposition"]);
    }
    header("Cache-Control: no-store");
    echo $out;
    exit;
}

/* ---------------------------------------------------------------- assets */
if (isset($_GET["asset"])) {
    $name = (string)$_GET["asset"];
    if (!preg_match('/^[A-Za-z0-9_.\/-]+$/', $name) || strpos($name, "..") !== false) {
        fs_fail(400, "bad asset");
    }
    list($out, $code, $rh, $err) = fs_fetch($FLOWSIGHT_BASE . "/static/" . $name);
    if ($out === null || $code !== 200) {
        http_response_code(404);
        exit;
    }
    header("Content-Type: " . ($rh["content-type"] ?? "application/octet-stream"));
    header("Cache-Control: " . (strpos($name, "/") !== false ? "private, max-age=31536000, immutable" : "no-cache"));
    echo $out;
    exit;
}

/* ---------------------------------------------------------------- app shell */
if (isset($_GET["app"])) {
    list($out, $code, $rh, $err) = fs_fetch($FLOWSIGHT_BASE . "/static/index.html");
    if ($out === null || $code !== 200) {
        header("Content-Type: text/plain");
        http_response_code(502);
        echo "flowsightd is not running" . ($err ? ": " . $err : "") . "\nStart it under Services or run: service flowsight start";
        exit;
    }
    $csrf = (new LegacyCSRF())->getToken();
    $hostTheme = (isset($_GET["theme"]) && in_array($_GET["theme"], ["light", "dark"], true)) ? $_GET["theme"] : "";
    $boot = "<script>window.FS_API_BASE='flowsight.php?api=';window.FS_CSRF=" . json_encode($csrf["token"])
        . ";window.FS_HOST_THEME=" . json_encode($hostTheme) . ";</script>";
    $html = str_replace("/static/", "flowsight.php?asset=", $out);
    $html = str_replace("<head>", "<head>" . $boot, $html);
    header("Content-Type: text/html; charset=utf-8");
    header("Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        . "img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'self'");
    echo $html;
    exit;
}

/* ---------------------------------------------------------------- page */
$pageName = isset($_GET['page']) ? ucfirst(preg_replace('/[^A-Za-z0-9 ]/', ' ', $_GET['page'])) : gettext("Overview");
$pgtitle = [gettext("FlowSight"), $pageName];
include("head.inc");
?>
<body>
<?php include("fbegin.inc"); ?>
<style>
  #fs-frame { width: 100%; height: 640px; border: 0; background: transparent; border-radius: 6px; overflow: hidden; }
  .page-content-main { padding-top: 6px !important; }
</style>
<section class="page-content-main">
  <div class="container-fluid">
    <div class="row">
      <section class="col-xs-12">
        <iframe id="fs-frame" data-src="flowsight.php?app=1" data-page="<?= isset($_GET['page']) ? htmlspecialchars(preg_replace('/[^A-Za-z0-9_\/?=&.-]/', '', $_GET['page'])) : '' ?>"
                title="FlowSight" referrerpolicy="same-origin" scrolling="no"></iframe>
        <script>
        (function () {
          // Tell the app whether the OPNsense theme around it is light or dark, from the
          // page's actual background colour, so every theme (including opnsense-auto) is handled.
          var f = document.getElementById('fs-frame');
          function tone() {
            var c = getComputedStyle(document.body).backgroundColor.match(/\d+(\.\d+)?/g) || [255, 255, 255];
            var l = (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255;
            return l < 0.5 ? 'dark' : 'light';
          }
          var t = tone();
          f.src = f.dataset.src + '&theme=' + t + (f.dataset.page ? '#' + f.dataset.page : '');
          // The app reports its height; the frame follows so the OPNsense page scrolls, not the frame.
          window.addEventListener('message', function (e) {
            if (e.source !== f.contentWindow || !e.data || !e.data.fsHeight) return;
            f.style.height = Math.max(480, Math.ceil(e.data.fsHeight) + 4) + 'px';
          });
          var mq = window.matchMedia('(prefers-color-scheme: dark)');
          function push() { var n = tone(); if (n !== t) { t = n; f.contentWindow.postMessage({ fsTheme: t }, location.origin); } }
          if (mq.addEventListener) mq.addEventListener('change', function () { setTimeout(push, 100); });
          new MutationObserver(function () { setTimeout(push, 100); }).observe(document.body, { attributes: true, attributeFilter: ['class', 'data-theme', 'style'] });
        })();
        </script>
      </section>
    </div>
  </div>
</section>
<?php include("foot.inc"); ?>
