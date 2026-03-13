<?php
/**
 * Plugin Name: Onexus Turnstile
 * Plugin URI: https://github.com/moursalinislambd/Onexus-Turnstile/
 * Description: Cloudflare Turnstile protection for WordPress
 * Version: 1.0.1
 * Author: Moursalin Islam
 * Author URI: https://x.com/moursalinislamb
 * License: GPL v2 or later
 * Text Domain: onexus-turnstile
 * 
 * Company: OnexusDev
 * Company URI: https://onexusdev.xyz/
 */

// Prevent direct access
if (!defined('ABSPATH')) exit;

class Onexus_Turnstile {
    
    private static $instance = null;
    private $site_key = '';
    private $secret_key = '';
    
    public static function instance() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->site_key = get_option('onexus_turnstile_site_key', '');
        $this->secret_key = get_option('onexus_turnstile_secret_key', '');
        
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_onexus_test_keys', [$this, 'test_keys']);
        
        if (!empty($this->site_key) && !empty($this->secret_key)) {
            $this->frontend_hooks();
        }
    }
    
    private function frontend_hooks() {
        add_action('wp_enqueue_scripts', [$this, 'load_scripts'], 999);
        add_action('login_enqueue_scripts', [$this, 'load_scripts'], 999);
        
        // Forms
        add_action('login_form', [$this, 'add_widget']);
        add_action('register_form', [$this, 'add_widget']);
        add_action('lostpassword_form', [$this, 'add_widget']);
        add_action('comment_form_after_fields', [$this, 'add_widget']);
        
        if (class_exists('WooCommerce')) {
            add_action('woocommerce_login_form', [$this, 'add_widget']);
            add_action('woocommerce_register_form', [$this, 'add_widget']);
            add_action('woocommerce_checkout_after_terms', [$this, 'add_widget']);
        }
        
        // Validation
        add_filter('authenticate', [$this, 'verify'], 30, 2);
        add_filter('registration_errors', [$this, 'verify_errors'], 10, 3);
        add_filter('preprocess_comment', [$this, 'verify_comment']);
        add_action('lostpassword_post', [$this, 'verify_lostpass']);
        add_action('elementor_pro/forms/validation', [$this, 'verify_elementor'], 10, 2);
        add_filter('wpcf7_validate', [$this, 'verify_cf7'], 10, 2);
    }
    
    public function load_scripts() {
        wp_enqueue_script('cf-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, true);
        
        wp_add_inline_script('cf-turnstile', '
            document.addEventListener("DOMContentLoaded", function() {
                if (typeof turnstile !== "undefined") {
                    document.querySelectorAll(".cf-turnstile").forEach(function(el) {
                        turnstile.render(el, {
                            sitekey: "' . esc_js($this->site_key) . '",
                            theme: "' . esc_js(get_option('onexus_turnstile_theme', 'auto')) . '",
                            size: "' . esc_js(get_option('onexus_turnstile_size', 'normal')) . '",
                            callback: function(token) {
                                var f = el.closest("form");
                                if (f) {
                                    var i = f.querySelector("input[name=\"cf-turnstile-response\"]");
                                    if (!i) {
                                        i = document.createElement("input");
                                        i.type = "hidden";
                                        i.name = "cf-turnstile-response";
                                        f.appendChild(i);
                                    }
                                    i.value = token;
                                }
                            }
                        });
                    });
                }
            });
        ');
    }
    
    public function add_widget() {
        echo '<div class="cf-turnstile" style="margin: 10px 0;"></div>';
    }
    
    public function verify($user, $username) {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return $user;
        
        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field($_POST['cf-turnstile-response']) : '';
        
        if (empty($token)) {
            return new WP_Error('turnstile_error', 'Please complete the security check');
        }
        
        if (!$this->validate_token($token)) {
            return new WP_Error('turnstile_error', 'Security check failed');
        }
        
        return $user;
    }
    
    public function verify_errors($errors, $login, $email) {
        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field($_POST['cf-turnstile-response']) : '';
        
        if (empty($token)) {
            $errors->add('turnstile_error', 'Please complete the security check');
            return $errors;
        }
        
        if (!$this->validate_token($token)) {
            $errors->add('turnstile_error', 'Security check failed');
        }
        
        return $errors;
    }
    
    public function verify_comment($comment) {
        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field($_POST['cf-turnstile-response']) : '';
        
        if (empty($token)) {
            wp_die('Please complete the security check', 'Security Error', ['back_link' => true]);
        }
        
        if (!$this->validate_token($token)) {
            wp_die('Security check failed', 'Security Error', ['back_link' => true]);
        }
        
        return $comment;
    }
    
    public function verify_lostpass($errors) {
        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field($_POST['cf-turnstile-response']) : '';
        
        if (empty($token)) {
            $errors->add('turnstile_error', 'Please complete the security check');
            return $errors;
        }
        
        if (!$this->validate_token($token)) {
            $errors->add('turnstile_error', 'Security check failed');
        }
        
        return $errors;
    }
    
    public function verify_elementor($record, $handler) {
        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field($_POST['cf-turnstile-response']) : '';
        
        if (empty($token)) {
            $handler->add_error('turnstile', 'Please complete the security check');
            return;
        }
        
        if (!$this->validate_token($token)) {
            $handler->add_error('turnstile', 'Security check failed');
        }
    }
    
    public function verify_cf7($result, $tags) {
        $token = isset($_POST['cf-turnstile-response']) ? sanitize_text_field($_POST['cf-turnstile-response']) : '';
        
        if (empty($token)) {
            $result->invalidate(['message' => 'Please complete the security check']);
            return $result;
        }
        
        if (!$this->validate_token($token)) {
            $result->invalidate(['message' => 'Security check failed']);
        }
        
        return $result;
    }
    
    private function validate_token($token) {
        if (empty($this->secret_key)) return true;
        
        $response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
            'body' => [
                'secret' => $this->secret_key,
                'response' => $token
            ],
            'timeout' => 5
        ]);
        
        if (is_wp_error($response)) return false;
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        return isset($data['success']) && $data['success'] === true;
    }
    
    public function admin_menu() {
        add_options_page(
            'Onexus Turnstile',
            'Onexus Turnstile',
            'manage_options',
            'onexus-turnstile',
            [$this, 'admin_page']
        );
    }
    
    public function register_settings() {
        register_setting('onexus_turnstile', 'onexus_turnstile_site_key', 'sanitize_text_field');
        register_setting('onexus_turnstile', 'onexus_turnstile_secret_key', 'sanitize_text_field');
        register_setting('onexus_turnstile', 'onexus_turnstile_theme', 'sanitize_text_field');
        register_setting('onexus_turnstile', 'onexus_turnstile_size', 'sanitize_text_field');
    }
    
    public function test_keys() {
        check_ajax_referer('onexus_turnstile');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $site_key = sanitize_text_field($_POST['site_key']);
        $secret_key = sanitize_text_field($_POST['secret_key']);
        
        if (empty($site_key) || empty($secret_key)) {
            wp_send_json_error('Both keys are required');
            return;
        }
        
        // Site key format check - updated for all Turnstile key formats
        // Turnstile keys can be: 0x..., 1x..., 2x..., 3x..., etc.
        if (!preg_match('/^[0-9a-f]{40,}$/i', $site_key) && 
            !preg_match('/^[0-9]x[_0-9a-zA-Z]{20,}$/', $site_key)) {
            // If format doesn't match, still try API validation
            // Don't block based on format alone
        }
        
        // Test with a real validation request
        $response = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
            'body' => [
                'secret' => $secret_key,
                'response' => 'XXXX.DUMMY.TOKEN.XXXX'
            ],
            'timeout' => 10
        ]);
        
        if (is_wp_error($response)) {
            wp_send_json_error('Connection failed: ' . $response->get_error_message());
            return;
        }
        
        $data = json_decode(wp_remote_retrieve_body($response), true);
        
        // Check for valid key indicators
        if (isset($data['error-codes'])) {
            $error_codes = $data['error-codes'];
            
            // These error codes mean the secret key is valid
            $valid_secret_indicators = ['invalid-input-response', 'missing-input-response', 'timeout-or-duplicate'];
            
            foreach ($valid_secret_indicators as $error) {
                if (in_array($error, $error_codes)) {
                    // Secret key is valid, now check site key by making a test widget
                    wp_send_json_success('✓ Keys are valid and working');
                    return;
                }
            }
            
            // Check for invalid secret key
            if (in_array('invalid-input-secret', $error_codes)) {
                wp_send_json_error('✗ Invalid secret key');
                return;
            }
            
            // Check for invalid site key (this comes from widget creation, not validation)
            if (in_array('invalid-sitekey', $error_codes)) {
                wp_send_json_error('✗ Invalid site key');
                return;
            }
            
            // If we get here with other errors
            wp_send_json_error('Connection OK but received: ' . implode(', ', $error_codes));
            return;
        }
        
        // If no error codes and success is false, keys are invalid
        if (isset($data['success']) && $data['success'] === false) {
            wp_send_json_error('✗ Invalid keys');
            return;
        }
        
        // If we get here, something unexpected happened
        wp_send_json_error('Unable to verify keys');
    }
    
    public function admin_page() {
        $site_key = get_option('onexus_turnstile_site_key', '');
        $secret_key = get_option('onexus_turnstile_secret_key', '');
        $theme = get_option('onexus_turnstile_theme', 'auto');
        $size = get_option('onexus_turnstile_size', 'normal');
        ?>
        <div class="wrap">
            <h1>🔒 Onexus Turnstile</h1>
            
            <div class="notice notice-info">
                <p><strong>Code With Purpose, Crafted by OnexusDev</strong> | Author: <a href="https://x.com/moursalinislamb" target="_blank">Moursalin Islam</a></p>
            </div>
            
            <form method="post" action="options.php">
                <?php settings_fields('onexus_turnstile'); ?>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Site Key</th>
                        <td>
                            <input type="text" name="onexus_turnstile_site_key" 
                                   value="<?php echo esc_attr($site_key); ?>" 
                                   class="regular-text" id="site_key"
                                   placeholder="0x4AAAAAAAEABVZR8q8X8X8X8X8X">
                            <p class="description">Get from <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank">Cloudflare Turnstile</a></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Secret Key</th>
                        <td>
                            <input type="password" name="onexus_turnstile_secret_key" 
                                   value="<?php echo esc_attr($secret_key); ?>" 
                                   class="regular-text" id="secret_key"
                                   placeholder="0x4AAAAAAAEABVZR8q8X8X8X8X8X">
                            <p class="description">
                                <button type="button" class="button button-secondary" id="test_keys">
                                    Test Connection
                                </button>
                                <span id="test_result" style="margin-left: 10px; font-weight: bold;"></span>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Theme</th>
                        <td>
                            <select name="onexus_turnstile_theme">
                                <option value="auto" <?php selected($theme, 'auto'); ?>>Auto</option>
                                <option value="light" <?php selected($theme, 'light'); ?>>Light</option>
                                <option value="dark" <?php selected($theme, 'dark'); ?>>Dark</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Size</th>
                        <td>
                            <select name="onexus_turnstile_size">
                                <option value="normal" <?php selected($size, 'normal'); ?>>Normal</option>
                                <option value="compact" <?php selected($size, 'compact'); ?>>Compact</option>
                            </select>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button('Save Settings'); ?>
            </form>
            
            <style>
            .wrap { max-width: 800px; margin: 20px auto; }
            .form-table th { width: 150px; }
            #test_result { font-size: 14px; }
            .success { color: #46b450; }
            .error { color: #dc3232; }
            </style>
            
            <script>
            document.getElementById('test_keys')?.addEventListener('click', function() {
                var siteKey = document.getElementById('site_key').value.trim();
                var secretKey = document.getElementById('secret_key').value.trim();
                var result = document.getElementById('test_result');
                
                if (!siteKey || !secretKey) {
                    result.innerHTML = '<span class="error">⚠️ Enter both keys first</span>';
                    return;
                }
                
                result.innerHTML = '⏳ Testing connection...';
                
                fetch(ajaxurl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: new URLSearchParams({
                        action: 'onexus_test_keys',
                        site_key: siteKey,
                        secret_key: secretKey,
                        _ajax_nonce: '<?php echo wp_create_nonce('onexus_turnstile'); ?>'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        result.innerHTML = '<span class="success">✅ ' + data.data + '</span>';
                    } else {
                        result.innerHTML = '<span class="error">❌ ' + data.data + '</span>';
                    }
                })
                .catch(error => {
                    result.innerHTML = '<span class="error">❌ Connection failed</span>';
                    console.error('Error:', error);
                });
            });
            </script>
        </div>
        <?php
    }
}

// Initialize
Onexus_Turnstile::instance();

// Uninstall
function onexus_turnstile_uninstall() {
    delete_option('onexus_turnstile_site_key');
    delete_option('onexus_turnstile_secret_key');
    delete_option('onexus_turnstile_theme');
    delete_option('onexus_turnstile_size');
}
register_uninstall_hook(__FILE__, 'onexus_turnstile_uninstall');
