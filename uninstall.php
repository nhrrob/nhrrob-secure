<?php
/**
 * Fired when the plugin is deleted.
 *
 * @package NHRRob\Secure
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

/**
 * Remove everything this plugin stored on the current site.
 *
 * @return void
 */
function nhrrob_secure_uninstall_site() {
	global $wpdb;

	// Scheduled events go either way: with the plugin deleted nothing is left to run them.
	foreach ( [ 'vulnerability_check', 'scan', 'summary', 'vulnerability_scan_cron', 'daily_cleanup' ] as $nhrrob_secure_hook ) {
		wp_clear_scheduled_hook( 'nhrrob_secure_' . $nhrrob_secure_hook );
	}

	$settings = get_option( 'nhrrob_secure_settings', [] );
	if ( is_array( $settings ) && isset( $settings['delete_on_uninstall'] ) && ! $settings['delete_on_uninstall'] ) {
		return; // The owner asked to keep the data.
	}

	foreach ( [ 'settings', 'activity', 'state', 'scan', 'migrating' ] as $nhrrob_secure_name ) {
		delete_option( 'nhrrob_secure_' . $nhrrob_secure_name );
	}

	// Options and transients of versions before 2.0.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall cleanup of this plugin's own rows.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( 'nhrrob_secure_' ) . '%',
			$wpdb->esc_like( '_transient_nhrrob_secure_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_nhrrob_secure_' ) . '%',
			$wpdb->esc_like( '_transient_nhrrob_2fa_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_nhrrob_2fa_' ) . '%'
		)
	);

	// The audit table versions before 2.0 created.
	$nhrrob_secure_table = $wpdb->prefix . 'nhrrob_audit_log';
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- drops a table an older version of this plugin created; the name is built from $wpdb->prefix and a literal.
	$wpdb->query( "DROP TABLE IF EXISTS {$nhrrob_secure_table}" );
}

if ( is_multisite() ) {
	foreach ( get_sites(
		[
			'fields' => 'ids',
			'number' => 0,
		]
	) as $nhrrob_secure_site_id ) {
		switch_to_blog( $nhrrob_secure_site_id );
		nhrrob_secure_uninstall_site();
		restore_current_blog();
	}
} else {
	nhrrob_secure_uninstall_site();
}

delete_site_transient( 'nhrrob_secure_network' );

// User meta is shared by the whole network: two-factor secrets, recovery codes and activity stamps.
$nhrrob_secure_settings = get_option( 'nhrrob_secure_settings', false );
if ( false === $nhrrob_secure_settings ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall cleanup of this plugin's own user meta.
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( 'nhrrob_secure_' ) . '%' ) );
}

// Rules this plugin wrote to .htaccess. The file lives in the site's home folder,
// which is not ABSPATH when WordPress is installed in its own directory.
require_once ABSPATH . 'wp-admin/includes/file.php';
$nhrrob_secure_htaccess = get_home_path() . '.htaccess';
if ( file_exists( $nhrrob_secure_htaccess ) && wp_is_writable( $nhrrob_secure_htaccess ) ) {
	require_once ABSPATH . 'wp-admin/includes/misc.php';
	insert_with_markers( $nhrrob_secure_htaccess, 'NHRRob Secure', [] );
}
