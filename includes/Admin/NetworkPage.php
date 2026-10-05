<?php
/**
 * Network Admin overview for multisite.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Settings;
use NHRRob\Secure\Services\Checks;
use NHRRob\Secure\Services\Vulnerabilities;

/**
 * Network Admin → Settings → Secure: every site's score and key settings in
 * one table, with a link into each site's own screen. Settings stay per site;
 * this page only reads.
 */
class NetworkPage {

	const MAX_SITES = 50;
	const CACHE     = 'nhrrob_secure_network';

	/**
	 * Hook the network menu.
	 *
	 * @return void
	 */
	public function init() {
		add_action( 'network_admin_menu', [ $this, 'register_menu' ] );
		add_action( 'network_admin_edit_nhrrob_secure_copy', [ $this, 'handle_copy' ] );
	}

	/**
	 * Register the page.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_submenu_page(
			'settings.php',
			__( 'Secure', 'nhrrob-secure' ),
			__( 'Secure', 'nhrrob-secure' ),
			'manage_network_options',
			AppPage::SLUG,
			[ $this, 'render' ]
		);
	}

	/**
	 * One row per site.
	 *
	 * @return array[]
	 */
	public static function rows() {
		// Running every check for every site is a lot of work for one page view; a few minutes old is fine here.
		$cached = get_site_transient( self::CACHE );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$rows  = [];
		$sites = get_sites(
			[
				'number'   => self::MAX_SITES,
				'archived' => 0,
				'deleted'  => 0,
			]
		);
		foreach ( $sites as $site ) {
			switch_to_blog( (int) $site->blog_id );
			Settings::flush();
			$checks = Checks::run();
			$failed = 0;
			foreach ( $checks as $check ) {
				if ( ! $check['passed'] ) {
					++$failed;
				}
			}
			$vuln   = Vulnerabilities::results();
			$rows[] = [
				'id'      => (int) $site->blog_id,
				'name'    => get_bloginfo( 'name' ),
				'url'     => home_url( '/' ),
				'open'    => admin_url( 'tools.php?page=' . AppPage::SLUG ),
				'score'   => Checks::score( $checks ),
				'failed'  => $failed,
				'vulns'   => count( $vuln['items'] ),
				'limit'   => (bool) Settings::get( 'limit_login' ),
				'twofa'   => (bool) Settings::get( 'twofa_enabled' ),
				'login'   => (bool) Settings::get( 'login_url_enabled' ),
				'filter'  => (string) Settings::get( 'request_filter' ),
				'checked' => (bool) Settings::exists(),
			];
			restore_current_blog();
		}
		Settings::flush();
		set_site_transient( self::CACHE, $rows, 5 * MINUTE_IN_SECONDS );
		return $rows;
	}

	/**
	 * Settings that stay each site's own when one site's settings are copied
	 * to the others: the moved login address (tested per site), file
	 * protection (one .htaccess), address rules and internal state.
	 *
	 * @var string[]
	 */
	const PER_SITE = [ 'db_version', 'safe_mode', 'login_url_enabled', 'login_slug', 'protect_files', 'ip_rules', 'request_filter_since', 'password_force', 'upgrade_notice' ];

	/**
	 * Copy one site's settings to every other site of the network.
	 *
	 * @param int $source_id Site to copy from.
	 * @return int Number of sites changed.
	 */
	public static function copy_settings( $source_id ) {
		if ( ! get_site( $source_id ) ) {
			return 0;
		}
		switch_to_blog( $source_id );
		Settings::flush();
		$shared = array_diff_key( Settings::all(), array_flip( self::PER_SITE ) );
		restore_current_blog();

		$count = 0;
		foreach ( get_sites(
			[
				'fields'   => 'ids',
				'number'   => 0,
				'archived' => 0,
				'deleted'  => 0,
			]
		) as $site_id ) {
			if ( (int) $site_id === (int) $source_id ) {
				continue;
			}
			switch_to_blog( $site_id );
			Settings::flush();
			$own                = Settings::all();
			$next               = array_merge( $own, $shared );
			$next['db_version'] = \NHRRob_Secure::DB_VERSION;
			Settings::write( $next );
			\NHRRob\Secure\Services\Schedule::sync();
			\NHRRob\Secure\Services\Summary::sync();
			restore_current_blog();
			++$count;
		}
		Settings::flush();
		delete_site_transient( self::CACHE );
		return $count;
	}

	/**
	 * Handle the "copy settings" form.
	 *
	 * @return void
	 */
	public function handle_copy() {
		check_admin_referer( 'nhrrob_secure_copy' );
		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'nhrrob-secure' ), '', [ 'response' => 403 ] );
		}
		$count = self::copy_settings( isset( $_POST['source'] ) ? absint( $_POST['source'] ) : 0 );
		wp_safe_redirect( add_query_arg( [ 'page' => AppPage::SLUG, 'copied' => $count ], network_admin_url( 'settings.php' ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound
		exit;
	}

	/**
	 * Render the page.
	 *
	 * @return void
	 */
	public function render() {
		$rows  = self::rows();
		$yes   = __( 'On', 'nhrrob-secure' );
		$no    = __( 'Off', 'nhrrob-secure' );
		$modes = [
			'off'   => $no,
			'log'   => __( 'Log only', 'nhrrob-secure' ),
			'block' => __( 'Block', 'nhrrob-secure' ),
		];
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Secure', 'nhrrob-secure' ); ?></h1>
			<?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- a number that only selects a notice. ?>
			<?php if ( isset( $_GET['copied'] ) ) : ?>
				<div class="notice notice-success"><p>
					<?php
					/* translators: %d: number of sites. */
					echo esc_html( sprintf( _n( 'Settings copied to %d site.', 'Settings copied to %d sites.', absint( $_GET['copied'] ), 'nhrrob-secure' ), absint( $_GET['copied'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					?>
				</p></div>
			<?php endif; ?>
			<p><?php esc_html_e( 'Each site keeps its own settings. This page shows where every site stands; open a site to change it.', 'nhrrob-secure' ); ?></p>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Site', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'Score', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'To fix', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'Vulnerabilities', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'Limit login attempts', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'Two-factor', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'Login address moved', 'nhrrob-secure' ); ?></th>
						<th><?php esc_html_e( 'Request filter', 'nhrrob-secure' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $rows as $row ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $row['name'] ); ?></strong><br><?php echo esc_html( $row['url'] ); ?></td>
							<td><?php echo esc_html( $row['score'] ); ?> / 100</td>
							<td><?php echo esc_html( $row['failed'] ); ?></td>
							<td><?php echo esc_html( $row['vulns'] ); ?></td>
							<td><?php echo esc_html( $row['limit'] ? $yes : $no ); ?></td>
							<td><?php echo esc_html( $row['twofa'] ? $yes : $no ); ?></td>
							<td><?php echo esc_html( $row['login'] ? $yes : $no ); ?></td>
							<td><?php echo esc_html( isset( $modes[ $row['filter'] ] ) ? $modes[ $row['filter'] ] : $no ); ?></td>
							<td><a class="button" href="<?php echo esc_url( $row['open'] ); ?>"><?php esc_html_e( 'Open', 'nhrrob-secure' ); ?></a></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<h2><?php esc_html_e( 'Use one site\'s settings everywhere', 'nhrrob-secure' ); ?></h2>
			<p><?php esc_html_e( 'Copies every setting of the chosen site to all other sites. Each site keeps its own login address, file protection and address rules.', 'nhrrob-secure' ); ?></p>
			<form method="post" action="<?php echo esc_url( network_admin_url( 'edit.php?action=nhrrob_secure_copy' ) ); ?>">
				<?php wp_nonce_field( 'nhrrob_secure_copy' ); ?>
				<select name="source" aria-label="<?php esc_attr_e( 'Site to copy from', 'nhrrob-secure' ); ?>">
					<?php foreach ( $rows as $row ) : ?>
						<option value="<?php echo esc_attr( $row['id'] ); ?>"><?php echo esc_html( $row['name'] . ' — ' . $row['url'] ); ?></option>
					<?php endforeach; ?>
				</select>
				<?php submit_button( __( 'Copy to all sites', 'nhrrob-secure' ), 'secondary', 'submit', false, [ 'onclick' => 'return confirm(' . wp_json_encode( __( 'Replace the settings of every other site with this site\'s settings?', 'nhrrob-secure' ) ) . ');' ] ); ?>
			</form>
			<?php if ( count( $rows ) >= self::MAX_SITES ) : ?>
				<p class="description">
					<?php
					/* translators: %d: number of sites. */
					echo esc_html( sprintf( __( 'Showing the first %d sites.', 'nhrrob-secure' ), self::MAX_SITES ) );
					?>
				</p>
			<?php endif; ?>
		</div>
		<?php
	}
}
