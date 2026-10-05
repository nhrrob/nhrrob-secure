<?php
/**
 * A section of the app backed by one REST controller.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Interfaces\ModuleInterface;

/**
 * Generic module used for the built-in sections. Add-ons can use it too, or
 * implement ModuleInterface themselves.
 */
class Module implements ModuleInterface {

	/**
	 * Module id.
	 *
	 * @var string
	 */
	private $id;

	/**
	 * Nav label.
	 *
	 * @var string
	 */
	private $label;

	/**
	 * Controller class name.
	 *
	 * @var string
	 */
	private $controller;

	/**
	 * Set up the module.
	 *
	 * @param string $id         Module id.
	 * @param string $label      Nav label.
	 * @param string $controller Class extending Rest\RestController, or '' when the section shares another section's routes.
	 */
	public function __construct( $id, $label, $controller = '' ) {
		$this->id         = $id;
		$this->label      = $label;
		$this->controller = $controller;
	}

	/**
	 * Module id.
	 *
	 * @return string
	 */
	public function id() {
		return $this->id;
	}

	/**
	 * Nav label.
	 *
	 * @return string
	 */
	public function label() {
		return $this->label;
	}

	/**
	 * Capability required to see and use this module.
	 *
	 * @return string
	 */
	public function capability() {
		return 'manage_options';
	}

	/**
	 * Register the controller's routes.
	 *
	 * @return void
	 */
	public function register_routes() {
		if ( '' !== $this->controller ) {
			$controller = $this->controller;
			( new $controller() )->register();
		}
	}
}
