<?php
/**
 * Plugin Name: NHR Secure | Protect Admin, Debug Logs & Limit Logins
 * Plugin URI: http://wordpress.org/plugins/nhrrob-secure/
 * Description: Lightweight WordPress security plugin that protects your admin area, hides debug logs, and limits login attempts. Minimal code, maximum protection.
 * Author: Nazmul Hasan Robin
 * Author URI: https://profiles.wordpress.org/nhrrob/
 * Version: 1.0.4
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Text Domain: nhrrob-secure
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

// Load Composer autoloader
require_once __DIR__ . '/vendor/autoload.php';

/**
 * The main plugin class
 */
final class NHRRob_Secure {

    /**
     * Plugin version
     *
     * @var string
     */
    const version = '1.0.4';

    /**
     * Class constructor
     */
    private function __construct() {
        $this->define_constants();

        add_action( 'plugins_loaded', [ $this, 'init_plugin' ] );
    }

    /**
     * Initialize a singleton instance
     *
     * @return \NHRRob_Secure
     */
    public static function init() {
        static $instance = false;

        if ( ! $instance ) {
            $instance = new self();
        }

        return $instance;
    }

    /**
     * Define the required plugin constants
     *
     * @return void
     */
    public function define_constants() {
        define( 'NHRROB_SECURE_VERSION', self::version );
        define( 'NHRROB_SECURE_FILE', __FILE__ );
        define( 'NHRROB_SECURE_PATH', __DIR__ );
        define( 'NHRROB_SECURE_PLUGIN_DIR', plugin_dir_path( NHRROB_SECURE_FILE ) );
        define( 'NHRROB_SECURE_URL', plugins_url( '', NHRROB_SECURE_FILE ) );
        define( 'NHRROB_SECURE_ASSETS', NHRROB_SECURE_URL . '/assets' );
    }

    /**
     * Initialize the plugin
     *
     * @return void
     */
    public function init_plugin() {
        
        // Initialize security features
        new \NHRRob\Secure\Security();

        // Initialize assets
        new \NHRRob\Secure\Assets();

        // Initialize REST API
        new \NHRRob\Secure\Admin\Api();

        // Initialize admin menu
        if ( is_admin() ) {
            new \NHRRob\Secure\Admin();
        }
    }
}


/**
 * Initializes the main plugin
 *
 * @return \NHRRob_Secure
 */
function nhrrob_secure() {
    return NHRRob_Secure::init();
}

// Call the plugin
nhrrob_secure();