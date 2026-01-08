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
        add_action( 'admin_menu', [ $this, 'register_menu' ] );
    }

    /**
     * Register admin menu
     */
    public function register_menu() {
        add_management_page(
            __( 'NHR Secure Settings', 'nhrrob-secure' ),
            __( 'NHR Secure', 'nhrrob-secure' ),
            'manage_options',
            'nhrrob-secure-settings',
            [ $this, 'render_page' ]
        );
    }

    /**
     * Render settings page
     */
    public function render_page() {
        ?>
        <div class="wrap">
            <div id="nhrrob-secure-settings-root"></div>
        </div>
        <?php
    }
}
