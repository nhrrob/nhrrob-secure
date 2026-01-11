<?php

namespace NHRRob\Secure\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}


/**
 * REST API handler class
 */
class Api {
    
    /**
     * Initialize the class
     */
    public function __construct() {
        add_action( 'rest_api_init', [ $this, 'register_routes' ] );
    }

    /**
     * Register REST API endpoints
     */
    public function register_routes() {
        // Get settings
        register_rest_route( 'nhrrob-secure/v1', '/settings', [
            'methods' => 'GET',
            'callback' => [ $this, 'get_settings' ],
            'permission_callback' => function() {
                return current_user_can( 'manage_options' );
            },
        ]);

        // Update settings
        register_rest_route( 'nhrrob-secure/v1', '/settings', [
            'methods' => 'POST',
            'callback' => [ $this, 'update_settings' ],
            'permission_callback' => function() {
                return current_user_can( 'manage_options' );
            },
            'args' => [
                'nhrrob_secure_limit_login_attempts' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_login_attempts_limit' => [
                    'type' => 'integer',
                    'sanitize_callback' => 'absint',
                ],
                'nhrrob_secure_custom_login_page' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_custom_login_url' => [
                    'type' => 'string',
                    'sanitize_callback' => 'sanitize_text_field',
                ],
                'nhrrob_secure_protect_debug_log' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_enable_proxy_ip' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_enable_2fa' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
                'nhrrob_secure_2fa_enforced_roles' => [
                    'type' => 'array',
                    'items' => [
                        'type' => 'string',
                    ],
                    'sanitize_callback' => function( $roles ) {
                        return is_array( $roles ) ? array_map( 'sanitize_text_field', $roles ) : [];
                    },
                ],
                'nhrrob_secure_dark_mode' => [
                    'type' => 'boolean',
                    'sanitize_callback' => 'rest_sanitize_boolean',
                ],
            ],
        ]);

    }

    /**
     * Get settings
     */
    public function get_settings() {
        return [
            'nhrrob_secure_limit_login_attempts' => (bool) get_option( 'nhrrob_secure_limit_login_attempts', 1 ),
            'nhrrob_secure_login_attempts_limit' => (int) get_option( 'nhrrob_secure_login_attempts_limit', 5 ),
            'nhrrob_secure_custom_login_page' => (bool) get_option( 'nhrrob_secure_custom_login_page', 1 ),
            'nhrrob_secure_custom_login_url' => get_option( 'nhrrob_secure_custom_login_url', '/hidden-access-52w' ),
            'nhrrob_secure_protect_debug_log' => (bool) get_option( 'nhrrob_secure_protect_debug_log', 1 ),
            'nhrrob_secure_enable_proxy_ip' => (bool) get_option( 'nhrrob_secure_enable_proxy_ip', false ),
            'nhrrob_secure_enable_2fa' => (bool) get_option( 'nhrrob_secure_enable_2fa', 0 ),
            'nhrrob_secure_2fa_enforced_roles' => (array) get_option( 'nhrrob_secure_2fa_enforced_roles', [] ),
            'nhrrob_secure_dark_mode' => (bool) get_option( 'nhrrob_secure_dark_mode', false ),
            'available_roles' => $this->get_available_roles(),
        ];
    }

    /**
     * Get available user roles
     */
    private function get_available_roles() {
        if ( ! function_exists( 'get_editable_roles' ) ) {
            require_once ABSPATH . 'wp-admin/includes/user.php';
        }
        
        $roles = get_editable_roles();
        $output = [];
        
        foreach ( $roles as $role_key => $role_data ) {
            $output[] = [
                'value' => $role_key,
                'label' => translate_user_role( $role_data['name'] ),
            ];
        }
        
        return $output;
    }

    /**
     * Update settings
     */
    public function update_settings( $request ) {
        $params = $request->get_params();

        foreach ( $params as $key => $value ) {
            if ( strpos( $key, 'nhrrob_secure_' ) === 0 ) {
                update_option( $key, $value );
            }
        }

        return $this->get_settings();
    }
}
