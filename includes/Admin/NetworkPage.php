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
