<?php
/*
 * Flowsight inside the OPNsense GUI.
 *
 * The Flowsight UI deliberately binds to 127.0.0.1 and ships no authentication.
 * Rather than exposing it on the LAN, this page proxies it from inside the web
 * GUI - which the firewall has already authenticated. The UI stays unreachable
 * from the network while remaining usable from the menu.
 *
 * Read-only by construction: only GET is proxied, and only to a fixed list of
 * endpoints. The Flowsight UI refuses writes anyway, but a proxy should not
 * rely on the thing behind it to enforce its own limits.
 */

require_once("guiconfig.inc");

$FLOWSIGHT_BASE = "http://127.0.0.1:8080";
$ALLOWED_API = array("status", "summary", "alerts", "policy", "hosts", "flows",
                     "apps", "devices", "policy_source", "config");
/* Endpoints that accept a POST body. Kept separate from the read list so a
   read-only endpoint can never be written to by accident. */
$ALLOWED_WRITE = array("policy_source", "policy_apply", "config");

function flowsight_fetch($url, $post_body = null)
{
    /* curl, not file_get_contents: allow_url_fopen is Off in OPNsense's php.ini */
    $ch = curl_init($url);
    curl_setopt_array($ch, array(
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 90,
    ));
    if ($post_body !== null) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Content-Type: application/json"));
    }
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    return array($body, $code, $err);
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_GET["api"])) {
    /* Writes reach the loopback UI only through this page, which the firewall
       has already authenticated. */
    $name = (string)$_GET["api"];
    header("Content-Type: application/json");
    if (!in_array($name, $ALLOWED_WRITE, true)) {
        http_response_code(403);
        echo json_encode(array("error" => "endpoint is not writable"));
        exit;
    }
    $body = file_get_contents("php://input");
    if (strlen($body) > 1000000) {
        http_response_code(413);
        echo json_encode(array("error" => "payload too large"));
        exit;
    }
    list($out, $code, $err) = flowsight_fetch($FLOWSIGHT_BASE . "/api/" . $name, $body);
    if ($out === false) {
        http_response_code(502);
        echo json_encode(array("error" => "flowsight-ui unreachable: " . $err));
        exit;
    }
    http_response_code($code ? $code : 200);
    echo $out;
    exit;
}

if (isset($_GET["api"])) {
    $name = (string)$_GET["api"];
    header("Content-Type: application/json");
    if (!in_array($name, $ALLOWED_API, true)) {
        http_response_code(404);
        echo json_encode(array("error" => "unknown endpoint"));
        exit;
    }
    list($body, $code, $err) = flowsight_fetch($FLOWSIGHT_BASE . "/api/" . $name);
    if ($body === false || $code !== 200) {
        http_response_code(502);
        echo json_encode(array("error" => "flowsight-ui unreachable on " .
            $FLOWSIGHT_BASE . ($err ? (": " . $err) : (" (HTTP " . $code . ")")) .
            ". Is the flowsight_ui service running?"));
        exit;
    }
    echo $body;
    exit;
}

list($html, $code, $err) = flowsight_fetch($FLOWSIGHT_BASE . "/");

include("head.inc");
echo '<body class="page-body">';
include("fbegin.inc");

if ($html === false || $code !== 200) {
    echo '<section class="page-content-main"><div class="content-box" '
       . 'style="padding:16px">'
       . '<p><strong>Flowsight UI is not reachable.</strong></p>'
       . '<p>Tried <code>' . htmlspecialchars($FLOWSIGHT_BASE) . '</code>'
       . ($err ? (' &mdash; ' . htmlspecialchars($err)) : (' &mdash; HTTP ' . (int)$code))
       . '.</p><p>Start it with <code>service flowsight_ui start</code>.</p>'
       . '</div></section>';
} else {
    /* The proxied page fetches '/api/x'; rewrite so those calls come back
       through this authenticated page rather than hitting the GUI root. */
    $html = str_replace("fetch(p)", "fetch(p)", $html);
    $html = str_replace("'/api/", "'flowsight.php?api=", $html);
    /* Strip the standalone document scaffolding - we are embedding it. */
    $html = preg_replace('#<!doctype html>#i', '', $html);
    $html = preg_replace('#<meta[^>]*>#i', '', $html);
    $html = preg_replace('#<title>.*?</title>#is', '', $html);
    echo '<section class="page-content-main"><div class="content-box" '
       . 'style="padding:0 8px">' . $html . '</div></section>';
}

include("foot.inc");
