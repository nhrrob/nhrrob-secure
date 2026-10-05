<?php
/**
 * Admin screen host for the React app.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\ModuleRegistry;
use NHRRob\Secure\Core\Settings;

/**
 * Registers Tools → Secure, renders the mount node and enqueues the compiled
 * app — and the small two-factor script on the user's own profile.
 */
class AppPage {

	const SLUG = 'nhrrob-secure';

	/**
	 * Registry supplying the sections the app renders.
	 *
	 * @var ModuleRegistry
	 */
	private $registry;

	/**
	 * Hook suffix of the screen.
	 *
	 * @var string|false
	 */
	private $hook = false;

	/**
	 * Store the registry.
	 *
	 * @param ModuleRegistry $registry Booted module registry.
	 */
	public function __construct( ModuleRegistry $registry ) {
		$this->registry = $registry;
	}

	/**
	 * Hook the menu and assets.
	 *
	 * @return void
	 */
	public function init() {
		add_action( 'admin_menu', [ $this, 'register_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue' ] );
		add_filter( 'plugin_action_links_' . plugin_basename( NHRROB_SECURE_FILE ), [ $this, 'action_links' ] );
	}

	/**
	 * Register the screen under Tools.
	 *
	 * @return void
	 */
	public function register_menu() {
		/**
		 * Filter the capability needed to open the Secure screen.
		 *
		 * @param string $capability Capability.
		 */
		$capability = apply_filters( 'nhrrob_secure_menu_capability', 'manage_options' );

		$this->hook = add_management_page(
			__( 'Secure', 'nhrrob-secure' ),
			__( 'Secure', 'nhrrob-secure' ),
			$capability,
			self::SLUG,
			[ $this, 'render' ]
		);
	}

	/**
	 * Add a Settings link on the Plugins screen.
	 *
	 * @param string[] $links Action links.
	 * @return string[]
	 */
	public function action_links( $links ) {
		$links[] = '<a href="' . esc_url( admin_url( 'tools.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Settings', 'nhrrob-secure' ) . '</a>';
		return $links;
	}

	/**
	 * Output the app's mount node.
	 *
	 * @return void
	 */
	public function render() {
		// The heading and wp-header-end marker make core move admin notices
		// inside .wrap; the app draws its own title bar.
		?>
		<div class="wrap nhrrob-secure-wrap">
			<h1 class="screen-reader-text"><?php esc_html_e( 'Secure', 'nhrrob-secure' ); ?></h1>
			<hr class="wp-header-end">
			<div id="nhrrob-secure-app"></div>
		</div>
		<?php
	}

	/**
	 * Enqueue the app on its screen and the two-factor script on the profile.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue( $hook ) {
		if ( 'profile.php' === $hook && Settings::get( 'twofa_enabled' ) ) {
			\NHRRob\Secure\Services\TwoFactor::enqueue_setup();
			return;
		}
		if ( ! $this->hook || $hook !== $this->hook ) {
			return;
		}

		$modules = [];
		foreach ( $this->registry->get_modules() as $module ) {
			$modules[] = [
				'id'    => $module->id(),
				'label' => $module->label(),
			];
		}

		$boot = [
			'restRoot'   => esc_url_raw( rest_url() ),
			'nonce'      => wp_create_nonce( 'wp_rest' ),
			'pluginName' => __( 'Secure', 'nhrrob-secure' ),
			'version'    => NHRROB_SECURE_VERSION,
			'modules'    => $modules,
			'updatesUrl' => admin_url( 'update-core.php' ),
			'profileUrl' => admin_url( 'profile.php#nhrrob-secure-2fa' ),
			'locale'     => str_replace( '_', '-', get_user_locale() ),
		];

		/**
		 * Filter the data the app boots with (window.nhrrobSecureApp).
		 *
		 * @param array $boot Boot payload.
		 */
		$boot = apply_filters( 'nhrrob_secure_app_boot', $boot );

		if ( $this->enqueue_bundle( 'index', 'nhrrobSecureApp', $boot ) ) {
			/**
			 * Fires after the app bundle is enqueued. Add-ons enqueue their own
			 * bundle here with 'nhrrob-secure-index' as a dependency.
			 */
			do_action( 'nhrrob_secure_app_enqueued' );
		}
	}

	/**
	 * Enqueue one compiled entry with its stylesheet and boot data.
	 *
	 * @param string $entry  Entry name in admin/build.
	 * @param string $object_name JavaScript global that receives the data.
	 * @param array  $data   Boot data.
	 * @return bool Whether the bundle exists.
	 */
	private function enqueue_bundle( $entry, $object_name, array $data ) {
		$dir   = NHRROB_SECURE_PATH . '/admin/build';
		$asset = $dir . '/' . $entry . '.asset.php';
		if ( ! file_exists( $asset ) ) {
			return false; // Not built yet — run `npm run build`.
		}
		$meta   = require $asset;
		$url    = NHRROB_SECURE_URL . '/admin/build';
		$handle = 'nhrrob-secure-' . $entry;

		wp_enqueue_script( $handle, $url . '/' . $entry . '.js', $meta['dependencies'], $meta['version'], true );
		wp_set_script_translations( $handle, 'nhrrob-secure' );
		wp_localize_script( $handle, $object_name, $data );

		// The build names a stylesheet style-{entry}.css when its source is style.scss, {entry}.css otherwise.
		foreach ( [ 'style-' . $entry . '.css', $entry . '.css' ] as $file ) {
			if ( file_exists( $dir . '/' . $file ) ) {
				// Own version: the asset hash covers the script only.
				wp_enqueue_style( $handle, $url . '/' . $file, [], (string) filemtime( $dir . '/' . $file ) );
				break;
			}
		}
		return true;
	}
}
