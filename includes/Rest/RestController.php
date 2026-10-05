<?php
/**
 * Base REST controller for nhrrob-secure/v1.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Rest;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared namespace, permission gates and route helper.
 *
 * Every route is gated on a capability, and routes that change files or act
 * across a network add a stricter gate on top.
 */
abstract class RestController {

	const NAMESPACE_V1 = 'nhrrob-secure/v1';

	/**
	 * Register this controller's routes.
	 *
	 * @return void
	 */
	abstract public function register();

	/**
	 * Route gate: administrators of this site.
	 *
	 * @return bool
	 */
	public function can_manage() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Stricter gate for actions that change files or reach beyond this site:
	 * on a multisite network only a super admin may run them.
	 *
	 * @return bool
	 */
	public function can_manage_files() {
		return current_user_can( 'manage_options' ) && ( ! is_multisite() || is_super_admin() );
	}

	/**
	 * Register one route.
	 *
	 * @param string   $path     Route path.
	 * @param string   $methods  HTTP methods.
	 * @param callable $callback Handler.
	 * @param array    $args     Argument schema.
	 * @param string   $gate     Permission method on this class.
	 * @return void
	 */
	protected function route( $path, $methods, $callback, array $args = [], $gate = 'can_manage' ) {
		register_rest_route(
			self::NAMESPACE_V1,
			$path,
			[
				'methods'             => $methods,
				'callback'            => $callback,
				'permission_callback' => [ $this, $gate ],
				'args'                => $args,
			]
		);
	}

	/**
	 * A required or optional string argument.
	 *
	 * @param bool $required Whether the argument is required.
	 * @return array
	 */
	protected function text( $required = true ) {
		return [
			'type'              => 'string',
			'required'          => $required,
			'sanitize_callback' => 'sanitize_text_field',
		];
	}
}
