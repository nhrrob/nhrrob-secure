<?php

namespace NHRRob\Secure\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}


/**
 * Menu handler class
 */
class Menu {
    
    /**
     * Initialize the class
     */
    public function __construct() {
        add_action( 'admin_menu', [ $this, 'admin_menu' ] );
    }

    /**
     * Register admin menu
     */
    public function admin_menu() {
        $parent_slug = 'nhrrob-secure-settings';
        $capability = apply_filters('nhrrob-secure/menu/capability', 'manage_options');

        $hook = add_submenu_page( 'tools.php', __( 'NHR Secure Settings', 'nhrrob-secure' ), __( 'NHR Secure', 'nhrrob-secure' ), $capability, $parent_slug, [ $this, 'settings_page' ] );

        add_action('admin_head-' . $hook, [$this, 'enqueue_assets']);
    }

    /**
     * Enqueue assets
     */
    public function enqueue_assets() {
        wp_enqueue_style( 'nhrrob-secure-admin' );
        
        wp_enqueue_script( 'nhrrob-secure-admin' );
    }

    /**
     * Render settings page
     */
    public function settings_page() {
        ?>
        <div class="wrap">
            <div id="nhrrob-secure-settings-root"></div>
        </div>
        <?php
    }
}
