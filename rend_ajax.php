<?php
require_once 'config.php';
session_start();
if (!function_exists('random_bytes')) {
    function random_bytes($length)
    {
        if (function_exists('openssl_random_pseudo_bytes')) {
            $strong = false;
            $bytes = random_bytes($length, $strong);
            if ($bytes !== false && $strong === true) {
                return $bytes;
            }
        }
        // Abort if no CSPRNG available
        throw new Exception('No secure random source available on this server.');
    }
}

// --- Compatibility: define hash_equals() if missing ---
if (!function_exists('hash_equals')) {
    function hash_equals($a, $b)
    {
        if (!is_string($a) || !is_string($b)) {
            return false;
        }
        $len = strlen($a);
        if ($len !== strlen($b)) {
            return false;
        }
        $res = $a ^ $b;
        $ret = 0;
        for ($i = $len - 1; $i >= 0; $i--) {
            $ret |= ord($res[$i]);
        }
        return $ret === 0;
    }
}

// --- Generate CSRF token if not already set ---
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Validate CSRF token ---
if (
    !isset($_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
) {
    echo "Invalid CSRF token. Please reload.";
    exit;
}
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

// Log file
$LOG_FILE = __DIR__ . '/logs/security_audit.log';
if (!file_exists(dirname($LOG_FILE))) {
    @mkdir(dirname($LOG_FILE), 0700, true);
}
ini_set('error_log', $LOG_FILE);

// Safe HTML escape helper
function h($s)
{
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

// Simple audit logger
function audit_log($msg)
{
    global $LOG_FILE;
    $clean = preg_replace('/[\r\n]+/', ' ', $msg);
    @file_put_contents($LOG_FILE, '[' . date('Y-m-d H:i:s') . '] ' . $clean . PHP_EOL, FILE_APPEND | LOCK_EX);
}

// Require DB connection (must set $link = mysqli_connect(...))

if (!isset($link) || !($link instanceof mysqli)) {
    audit_log("DB connection missing in config.php");
    http_response_code(500);
    exit('Server configuration error');
}
// ----------------------- CSRF validation -----------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed');
}

// ----------------------- Basic session integrity (optional but recommended) -----------------------
if (!isset($_SESSION['user_name'])) {
    audit_log('Unauthorized access attempt');
    http_response_code(401);
    exit('Unauthorized');
}
/* ----------------------- Collect & sanitize POST inputs ----------------------- */
$lottery_category_code = isset($_POST['sel_type']) ? trim(intval($_POST['sel_type'])) : '';
$total_reserved_plot_of_lottery_category_input = isset($_POST['sel_val']) ? trim(intval($_POST['sel_val'])) : '';
$person1 = isset($_POST['person1']) ? trim(intval($_POST['person1'])) : '';
$person2 = isset($_POST['person2']) ? trim(intval($_POST['person2'])) : '';
$person3 = isset($_POST['person3']) ? trim(intval($_POST['person3'])) : '';
$person4 = isset($_POST['person4']) ? trim(intval($_POST['person4'])) : '';

// Basic validation
if (
    $lottery_category_code === '' || $total_reserved_plot_of_lottery_category_input === '' ||
    $person1 === '' || $person2 === '' || $person3 === '' || $person4 === ''
) {
    audit_log('Invalid input fields by user ' . $_SESSION['user_name']);
    exit('<div class="alert alert-danger">Missing required fields.</div>');
}

// Ensure numeric where expected
if (!is_numeric($total_reserved_plot_of_lottery_category_input)) {
    audit_log('sel_val not numeric by user ' . $_SESSION['user_name']);
    exit('<div class="alert alert-danger">Invalid reserved plots number.</div>');
}
$total_reserved_plot_of_lottery_category_post = (int)$total_reserved_plot_of_lottery_category_input;

// Build seed_no exactly as original
$seed_no = $person1 . $person2 . $person3 . $person4;

/* ----------------------- Fetch category details (using columns you listed) ------------------------- */
$cat_stmt = mysqli_prepare($link, "SELECT category_code, category_e, category_h, sub_category, category_type, flag, reserved_flats, reserved_category, priority, status FROM lottery_category WHERE category_code = ? LIMIT 1");
if (!$cat_stmt) {
    audit_log('Prepare failed (category select): ' . mysqli_error($link));
    exit('<div class="alert alert-danger">Database error (category lookup).</div>');
}
mysqli_stmt_bind_param($cat_stmt, 's', $lottery_category_code);
mysqli_stmt_execute($cat_stmt);
$cat_res = mysqli_stmt_get_result($cat_stmt);
$cat_row = mysqli_fetch_assoc($cat_res);
mysqli_stmt_close($cat_stmt);

if (!$cat_row) {
    audit_log('Invalid category code requested by ' . $_SESSION['user_name'] . ': ' . $lottery_category_code);
    exit('<div class="alert alert-danger">Invalid category selected.</div>');
}

// Use reserved_flats from DB as canonical total_reserved_plot_of_lottery_category.
// If you still want to accept client-sent sel_val, you can compare/override — here we respect DB.
$total_reserved_plot_of_lottery_category = (int)$cat_row['reserved_flats'];
$lottery_category_name = $cat_row['category_e'] . '-' . $cat_row['sub_category'];

/* ----------------------- Winners and plots count logic ----------------------- */
// Count winners already selected
$stmt = mysqli_prepare($link, "SELECT COUNT(applicant_form_id) AS winner_count FROM applicant_form_detail WHERE lottery_category = ? AND flag = 1 AND approve_flag = 'A' AND emd_flag = 1 AND payment_flag = 1");
mysqli_stmt_bind_param($stmt, 's', $lottery_category_code);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$rc = mysqli_fetch_assoc($res);
$row_winner_count = $rc ?: array('winner_count' => 0);
mysqli_stmt_close($stmt);

// Total plots in flat table
$stmt = mysqli_prepare($link, "SELECT COUNT(flat_id) AS total_plots_for_lottery FROM flat WHERE approve = '1'");
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$rp = mysqli_fetch_assoc($res);
$row_total_plots_for_lottery = $rp ?: array('total_plots_for_lottery' => 0);
mysqli_stmt_close($stmt);

if ((int)$row_total_plots_for_lottery["total_plots_for_lottery"] < $total_reserved_plot_of_lottery_category) {
    echo '<div class="alert alert-danger">Reserved Plot\'s Count must be less than Existing Flats (' . h($row_total_plots_for_lottery["total_plots_for_lottery"]) . ')</div>';
    exit();
}

$stmt = mysqli_prepare($link, "SELECT COUNT(form_id) AS form_id FROM lottery_result_ph WHERE category = ?");
mysqli_stmt_bind_param($stmt, 's', $lottery_category_code);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$rw = mysqli_fetch_assoc($res);
$row_total_winner_lottery_category = $rw ?: array('form_id' => 0);
mysqli_stmt_close($stmt);
$total_winner_count_lottery_category = (int)$row_total_winner_lottery_category["form_id"];

$stmt = mysqli_prepare($link, "SELECT COUNT(applicant_form_id) AS approved_applicants FROM applicant_form_detail WHERE lottery_category = ? AND approve_flag = 'A' AND payment_flag = 1 AND emd_flag = 1");
mysqli_stmt_bind_param($stmt, 's', $lottery_category_code);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$ra = mysqli_fetch_assoc($res);
$row_total_approve_applicants_lottery_category = $ra ?: array('approved_applicants' => 0);
mysqli_stmt_close($stmt);
$approved_applicants = (int)$row_total_approve_applicants_lottery_category['approved_applicants'];

$limit = ($approved_applicants > $total_reserved_plot_of_lottery_category) ? $total_reserved_plot_of_lottery_category : $approved_applicants;

/* ----------------------- If lottery complete, show final UI and exit ----------------------- */
if ($total_winner_count_lottery_category >= $limit) {
    $upd_stmt = mysqli_prepare($link, "UPDATE lottery_category SET flag = 1 WHERE category_code = ?");
    if ($upd_stmt) {
        mysqli_stmt_bind_param($upd_stmt, "s", $lottery_category_code);
        mysqli_stmt_execute($upd_stmt);
        mysqli_stmt_close($upd_stmt);
    } else {
        audit_log('Failed to update lottery_category flag: ' . mysqli_error($link));
    }
$timestamp = microtime(true);

// server_secret: use openssl_random_pseudo_bytes for older PHP
$strong = false;
$rand = openssl_random_pseudo_bytes(32, $strong);
$server_secret_raw = hash('sha256', $rand . '|' . $timestamp . '|' . $seed_no);
$server_secret = hash('sha256', 'server-key-prefix' . $server_secret_raw);
$draw_seed = hash('sha256', $seed_no . '|' . $timestamp . '|' . $server_secret);
    echo '
    <div class="lottery-containerx">
        <div class="lottery-headerx">
            <h2><i class="fas fa-trophy"></i> Lottery Results</h2>
            <p>Category: ' . h($lottery_category_name) . '</p>
        </div>

        <div class="lottery-statsx">
            <div class="stat-boxx">
                <div class="stat-valuex">' . h($row_winner_count['winner_count']) . '</div>
                <div class="stat-labelx">Winners Selected</div>
            </div>
            <div class="stat-boxx">
                <div class="stat-valuex">' . h($limit) . '</div>
                <div class="stat-labelx">Total Plots Available</div>
            </div>
            <div class="stat-boxx">
                <div class="stat-valuex">' . h($seed_no) . '</div>
                <div class="stat-labelx">Lottery Seed Number</div>
            </div>
        </div>

        <div class="result-actionsx">
            <a href="run_time_result.php?val=' . urlencode($lottery_category_code) . '" target="_blank" class="result-btnx winners-btnx">
                <i class="fas fa-list-ol"></i> View Winners List
            </a>
        </div>
        <div class="result-actionsx">
            <form action="run_time_generate_waiting_list.php" method="post" target="_blank">
                <input type="hidden" name="lottery_category" value='.$lottery_category_code.'>
                <input type="hidden" name="draw_seed" value='.$draw_seed.'>
                <button type="submit" class="result-btnx winners-btnx">
                    <i class="fas fa-list-ol"></i> View Waiting List
                </button>
            </form>
        </div>


        <div class="lottery-completex">
            <i class="fas fa-check-circle"></i> Lottery for this category is now complete
        </div>
    </div>

    <input type="hidden" id="end" value="1" />';
    exit();
}
/* ----------------------- Fetch eligible applicants ----------------------- */
$applicants = array();
$stmt = mysqli_prepare($link, "SELECT applicant_form_id, applicant_name, relation_name FROM applicant_form_detail WHERE lottery_category = ? AND flag = 0 AND approve_flag = 'A' AND payment_flag = 1 AND emd_flag = 1 order by RAND()");
mysqli_stmt_bind_param($stmt, 's', $lottery_category_code);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
while ($r = mysqli_fetch_assoc($res)) {
    $applicants[$r['applicant_form_id']] = array(
        'name' => htmlspecialchars($r['applicant_name'], ENT_QUOTES, 'UTF-8'),
        'relation_name' => htmlspecialchars($r['relation_name'], ENT_QUOTES, 'UTF-8')
    );
}
mysqli_stmt_close($stmt);
$plots = array();
$stmt = mysqli_prepare($link, "SELECT flat_id, flat_no, plot_area_sqfeet, floor FROM flat WHERE flat_alloted_flag = 0 AND approve = '1'  order by RAND()");
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);

while ($r = mysqli_fetch_assoc($res)) {
    $plots[$r['flat_id']] = array(
        'flat_no' => $r['flat_no'],
        'floor' => $r['floor'],
        'area' => $r['plot_area_sqfeet']
    );
}
mysqli_stmt_close($stmt);

if (empty($applicants) || empty($plots)) {
    echo '<div class="alert alert-warning">No eligible applicants or flats found.</div>';
    exit();
}
$timestamp = microtime(true);
$strong = false;
$rand = openssl_random_pseudo_bytes(32, $strong);
$server_secret_raw = hash('sha256', $rand . '|' . $timestamp . '|' . $seed_no);
$server_secret = hash('sha256', 'server-key-prefix' . $server_secret_raw);
$draw_seed = hash('sha256', $seed_no . '|' . $timestamp . '|' . $server_secret);
$applicant_seed =  hash('sha256', $draw_seed . '|applicant');
/* ----------------------- Deterministic selection using HMAC ----------------------- */
$applicant_hash = array();
foreach ($applicants as $id => $name) {
    $applicant_hash[$id] = hash_hmac('sha256', (string)$id, $applicant_seed);
}
asort($applicant_hash, SORT_STRING);
$winner_id = key($applicant_hash);
$winner_name = $applicants[$winner_id]['name'];
$winner_relation_name = $applicants[$winner_id]['relation_name'];


$plot_seed = hash('sha256', $draw_seed . '|plot');


$flat_hash = array();
foreach ($plots as $flat_id => $flat_data) {
    $flat_hash[$flat_id] = hash_hmac('sha256', (string)$flat_id, $plot_seed);
}

asort($flat_hash, SORT_STRING);
$flat_id = key($flat_hash);
$flat_no = $plots[$flat_id]['flat_no'];
$floor_number = $plots[$flat_id]['floor'];
$flat_area_empty = $plots[$flat_id]['area'];
/* ----------------------- Insert lottery result and update flags inside a transaction ----------------------- */
$use_transaction = true;
if ($use_transaction && method_exists($link, 'begin_transaction')) {
    $link->begin_transaction();
} else {
    // attempt to set autocommit false as fallback
    @mysqli_autocommit($link, false);
}


try {
    // Insert into lottery_result_ph
    $stmt = mysqli_prepare(
        $link,
        "INSERT INTO lottery_result_ph (`form_id`, `applicant_name`, `relation_name`, `flat_id`, `flat_number`, `flat_area`, `flag`, `category`, `date`)
                                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)"
    );
    if (!$stmt) {
        throw new Exception('Prepare failed (insert lottery_result_ph): ' . mysqli_error($link));
    }
    $date_now = date('Y-m-d H:i:s');
    mysqli_stmt_bind_param(
        $stmt,
        'ississis',
        $winner_id,
        $winner_name,
        $winner_relation_name,
        $flat_id,
        $flat_no,
        $flat_area_empty,
        $lottery_category_code,
        $date_now
    );
    if (!mysqli_stmt_execute($stmt)) {
        throw new Exception('Execute failed (insert lottery_result_ph): ' . mysqli_stmt_error($stmt));
    }
    mysqli_stmt_close($stmt);

    // Update applicant_form_detail
    $stmt = mysqli_prepare($link, "UPDATE applicant_form_detail SET flag = 1 WHERE applicant_form_id = ?");
    if (!$stmt) throw new Exception('Prepare failed (update applicant): ' . mysqli_error($link));
    mysqli_stmt_bind_param($stmt, 's', $winner_id);
    if (!mysqli_stmt_execute($stmt)) throw new Exception('Execute failed (update applicant): ' . mysqli_stmt_error($stmt));
    mysqli_stmt_close($stmt);

    // Update flat
    $stmt = mysqli_prepare($link, "UPDATE flat SET flat_alloted_flag = 1 WHERE flat_id = ?");
    if (!$stmt) throw new Exception('Prepare failed (update flat): ' . mysqli_error($link));
    mysqli_stmt_bind_param($stmt, 's', $flat_id);
    if (!mysqli_stmt_execute($stmt)) throw new Exception('Execute failed (update flat): ' . mysqli_stmt_error($stmt));
    mysqli_stmt_close($stmt);

    // commit
    if ($use_transaction && method_exists($link, 'commit')) {
        $link->commit();
    } else {
        @mysqli_commit($link);
    }
} catch (Exception $e) {
    // rollback and log
    if ($use_transaction && method_exists($link, 'rollback')) {
        $link->rollback();
    } else {
        @mysqli_rollback($link);
    }
    audit_log('Transaction failed: ' . $e->getMessage());
    exit('<div class="alert alert-danger">An error occurred while saving results. Check logs.</div>');
}

/* ----------------------- Display result (styled HTML, sanitized) ----------------------- */
echo '
      <style>
        /* BEGIN inline CSS (kept identical to your provided style) */
        .lottery-containerx {
            max-width: 900px;
            margin: 30px auto;
            padding: 40px;
            background: linear-gradient(135deg, #ffffff 0%, #f9f9f9 100%);
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            font-family: "Poppins", sans-serif;
            border: 1px solid #e0e0e0;
            position: relative;
            overflow: hidden;
        }
        .lottery-containerx::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 8px;
            height: 100%;
            background: linear-gradient(to bottom, var(--primary-color), #992E2D);
        }
        .lottery-headerx { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #f0f0f0; }
        .lottery-headerx h2 { color: var(--primary-color); font-size: 32px; margin-bottom: 10px; font-weight: 700; display: flex; align-items: center; justify-content: center; gap: 15px; }
        .lottery-headerx p { color: #666; font-size: 18px; margin-top: 10px; }
        .lottery-statsx { display: flex; justify-content: space-around; margin: 40px 0; gap: 20px; flex-wrap: wrap; }
        .stat-boxx { text-align: center; padding: 25px 20px; background: white; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.05); flex: 1; min-width: 180px; transition: all 0.3s ease; border: 1px solid #f0f0f0; }
        .stat-boxx:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .stat-valuex { font-size: 36px; font-weight: 700; color: var(--primary-color); margin-bottom: 5px; line-height: 1; }
        .stat-labelx { font-size: 16px; color: #666; font-weight: 500; }
        .result-actionsx { display: flex; justify-content: center; gap: 25px; margin: 40px 0; flex-wrap: wrap; }
        .result-btnx { display: inline-flex; align-items: center; padding: 16px 30px; border-radius: 10px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; font-size: 16px; border: none; cursor: pointer; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .result-btnx i { margin-right: 12px; font-size: 20px; }
        .winners-btnx { background: linear-gradient(135deg, var(--primary-color) 0%, #992E2D 100%); color: white; }
        .winners-btnx:hover { transform: translateY(-3px); box-shadow: 0 8px 15px rgba(175, 35, 34, 0.3); background: linear-gradient(135deg, #992E2D 0%, var(--primary-color) 100%); }
        .waiting-btnx { background: linear-gradient(135deg, #6c757d 0%, #5a6268 100%); color: white; }
        .waiting-btnx:hover { transform: translateY(-3px); box-shadow: 0 8px 15px rgba(108, 117, 125, 0.3); background: linear-gradient(135deg, #5a6268 0%, #6c757d 100%); }
        .lottery-completex { text-align: center; margin-top: 30px; padding: 20px; background: #f0fff0; border-radius: 10px; color: #28a745; font-weight: 600; font-size: 18px; border: 1px solid #d4edda; display: flex; align-items: center; justify-content: center; gap: 10px; }
        .processingx { text-align: center; padding: 50px; background: white; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.05); max-width: 600px; margin: 30px auto; border: 1px solid #f0f0f0; }
        .processingx img { width: 100px; height: 100px; margin-bottom: 20px; }
        .processingx div { font-size: 20px; color: #333; font-weight: 500; margin-top: 20px; }
        .result-tablex { width: 100%; border-collapse: separate; border-spacing: 0; margin: 30px 0; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 5px 15px rgba(0,0,0,0.05); }
        .result-tablex th { background: var(--primary-color); color: white; padding: 18px; text-align: left; font-weight: 600; font-size: 16px; }
        .result-tablex td { padding: 16px; border-bottom: 1px solid #f0f0f0; color: #444; }
        .result-tablex tr:nth-child(even) { background-color: #f9f9f9; }
        .result-tablex tr:last-child td { border-bottom: none; }
        .result-tablex tr:hover { background-color: #f5f5f5; }
        @media (max-width: 768px) { .lottery-containerx { padding: 25px; border-radius: 12px; } .lottery-headerx h2 { font-size: 26px; } .stat-boxx { min-width: 120px; padding: 20px 15px; } .stat-valuex { font-size: 28px; } .result-actionsx { flex-direction: column; gap: 15px; } .result-btnx { width: 100%; justify-content: center; } }
        /* END inline CSS */
    </style>';

echo '
<div class="processingx">
  <img src="ring.gif" alt="Loading..." class="progress-gif">
  <div>Processing lottery results for <strong>' . h($lottery_category_name) . '</strong>...</div>
  <div class="live-counter">
    Winners Selected: <span id="winner_count">' . h($total_winner_count_lottery_category) . '</span> / ' . h($limit) . '
  </div>
</div>

<table class="result-tablex">
    <tr>
        <th ><center>Form Number</center></th>
        <th ><center>Applicant Name</center></th>
        <th ><center>Relation Name S/D/W </center></th>
        <th ><center>Plot Number</center></th>
    </tr>
    <tr>
        <td>' . h($winner_id) . '</td>
        <td>' . h($winner_name) . '</td>
        <td>' . h($winner_relation_name) . '</td>
        <td>' . h($flat_no) . '</td>
    </tr>
</table>';

// Optional: insert person_seed again to match original behavior (non-fatal if duplicate)
$stmt = mysqli_prepare($link, "INSERT INTO person_seed (`lottery_category_code`, `person1`, `person2`, `person3`, `person4`, `seed_no`, `timestamp`, `server_secret`, `draw_seed`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
if ($stmt) {
    $ts_str2 = (string)$timestamp;
    mysqli_stmt_bind_param($stmt, 'iiiiiiiss', $lottery_category_code, $person1, $person2, $person3, $person4, $seed_no, $ts_str2, $server_secret, $draw_seed);
    if (!mysqli_stmt_execute($stmt)) {
        audit_log('Second person_seed insert failed (ok if duplicate): ' . mysqli_stmt_error($stmt));
    }
    mysqli_stmt_close($stmt);
}

echo '<input type="hidden" id="end" value="0" />';


unset($applicants);
unset($plots);
unset($applicant_hash);
unset($flat_hash);
gc_collect_cycles();


// Close DB connection
mysqli_close($link);

// Audit log
audit_log("Lottery run by " . $_SESSION['user_name'] . " | Lottery Draw Category: $lottery_category_code | Applicant ID: $winner_id | PLOT NO : $flat_no");

exit();
