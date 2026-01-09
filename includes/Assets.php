<?php

namespace NHRRob\Secure;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}


/**
 * Assets handler class
 */
class Assets {
    
    /**
     * Class constructor
     */
    public function __construct() {
        add_action( 'admin_enqueue_scripts', [ $this, 'register_assets' ] );
        add_action( 'wp_enqueue_scripts', [ $this, 'register_assets' ] );
    }

    /**
     * All available scripts
     *
     * @return array
     */
    public function get_scripts() {
        $asset_file = NHRROB_SECURE_PLUGIN_DIR . 'build/admin.asset.php';
        
        if ( ! file_exists( $asset_file ) ) {
            return [];
        }

        $asset = require $asset_file;

        return [
            'nhrrob-secure-admin' => [
                'src'     => plugins_url( 'build/admin.js', NHRROB_SECURE_FILE ),
                'version' => $asset['version'],
                'deps'    => $asset['dependencies']
            ],
        ];
    }

    /**
     * All available styles
     *
     * @return array
     */
    public function get_styles() {
        $asset_file = NHRROB_SECURE_PLUGIN_DIR . 'build/admin.asset.php';
        
        if ( ! file_exists( $asset_file ) ) {
            return [];
        }

        $asset = require $asset_file;

        return [
            'nhrrob-secure-admin' => [
                'src'     => plugins_url( 'build/style-admin.css', NHRROB_SECURE_FILE ),
                'version' => $asset['version'],
                'deps'    => [ 'wp-components' ]
            ],
        ];
    }

    /**
     * Register scripts and styles
     *
     * @param string $hook Current admin page hook
     * @return void
     */
    public function register_assets( $hook ) {
        if ( $hook !== 'tools_page_nhrrob-secure-settings' ) {
            return;
        }

        $scripts = $this->get_scripts();
        $styles  = $this->get_styles();

        foreach ( $scripts as $handle => $script ) {
            $deps = isset( $script['deps'] ) ? $script['deps'] : [];
            wp_register_script( $handle, $script['src'], $deps, $script['version'], true );
        }

        foreach ( $styles as $handle => $style ) {
            $deps = isset( $style['deps'] ) ? $style['deps'] : [];
            wp_register_style( $handle, $style['src'], $deps, $style['version'] );
        }

        wp_localize_script( 'nhrrob-secure-admin', 'nhrrobSecureSettings', [
            'root'  => esc_url_raw( rest_url() ),
            'nonce' => wp_create_nonce( 'wp_rest' ),
        ]);
    }
}

