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
        add_filter( 'plugin_action_links_' . plugin_basename( NHRROB_SECURE_FILE ), [ $this, 'plugin_action_links' ] );
    }

    /**
     * Add settings link to the plugin action links
     *
     * @param array $links
     * @return array
     */
    public function plugin_action_links( $links ) {
        $links[] = '<a href="' . admin_url( 'tools.php?page=nhrrob-secure-settings' ) . '">' . __( 'Settings', 'nhrrob-secure' ) . '</a>';

        return $links;
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
        wp_enqueue_style( 'nhrrob-secure-admin-style' );
        
        wp_enqueue_script( 'nhrrob-secure-admin-script' );
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
