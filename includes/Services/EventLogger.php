<?php
/**
 * Hooks that feed the activity log.
 *
 * @package NHRRob\Secure
 */

namespace NHRRob\Secure\Services;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use NHRRob\Secure\Core\Activity;
use NHRRob\Secure\Core\Alerts;
use NHRRob\Secure\Core\Settings;

/**
 * Listens to WordPress and records the events that matter for security:
 * sign-ins, account changes, plugin and theme changes, and a short list of
 * critical site settings.
 */
class EventLogger {

	/**
	 * Site options worth an entry when they change.
	 *
	 * @var string[]
	 */
	const WATCHED_OPTIONS = [ 'users_can_register', 'default_role', 'siteurl', 'home', 'admin_email' ];

	/**
	 * How the current sign-in was completed, set by the two-factor step.
	 *
	 * @var string
	 */
	public static $login_kind = 'success';

	/**
	 * Register the hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'wp_login', [ $this, 'on_login' ], 10, 2 );
		add_action( 'wp_logout', [ $this, 'on_logout' ] );

		add_action( 'user_register', [ $this, 'on_user_created' ] );
		add_action( 'delete_user', [ $this, 'on_user_deleted' ] );
		add_action( 'set_user_role', [ $this, 'on_role_change' ], 10, 3 );
		add_action( 'profile_update', [ $this, 'on_profile_update' ], 10, 2 );
		add_action( 'after_password_reset', [ $this, 'on_password_reset' ] );

		add_action( 'activated_plugin', [ $this, 'on_plugin_activated' ] );
		add_action( 'deactivated_plugin', [ $this, 'on_plugin_deactivated' ] );
		add_action( 'deleted_plugin', [ $this, 'on_plugin_deleted' ], 10, 2 );
		add_action( 'deleted_theme', [ $this, 'on_theme_deleted' ], 10, 2 );
		add_action( 'switch_theme', [ $this, 'on_theme_switched' ] );
		add_action( 'upgrader_process_complete', [ $this, 'on_upgrade' ], 10, 2 );
		add_action( '_core_updated_successfully', [ $this, 'on_core_updated' ] );

		foreach ( self::WATCHED_OPTIONS as $option ) {
			add_action( 'update_option_' . $option, [ $this, 'on_option_change' ], 10, 3 );
		}
	}

	/**
	 * A user signed in.
	 *
	 * @param string   $login Username.
	 * @param \WP_User $user  User.
	 * @return void
	 */
	public function on_login( $login, $user ) {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		update_user_meta( $user->ID, 'nhrrob_secure_last_login', time() );
		update_user_meta( $user->ID, 'nhrrob_secure_last_activity', time() );
		Activity::record( 'login', self::$login_kind, $login, Activity::INFO, [ 'user' => $user->ID ] );
	}

	/**
	 * A user signed out.
	 *
	 * @param int $user_id User id (WordPress 5.5+).
	 * @return void
	 */
	public function on_logout( $user_id = 0 ) {
		if ( $user_id ) {
			Activity::record( 'login', 'logout', '', Activity::INFO, [ 'user' => (int) $user_id ] );
		}
	}

	/**
	 * A user account was created.
	 *
	 * @param int $user_id New user id.
	 * @return void
	 */
	public function on_user_created( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$is_admin = in_array( 'administrator', (array) $user->roles, true );
		Activity::record( 'user', 'created', $user->user_login, $is_admin ? Activity::CRITICAL : Activity::WARNING, [ 'detail' => implode( ', ', (array) $user->roles ) ] );
		if ( $is_admin ) {
			$this->alert_new_admin( $user );
		}
	}

	/**
	 * A user account is about to be deleted.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public function on_user_deleted( $user_id ) {
		$user = get_userdata( $user_id );
		if ( $user ) {
			Activity::record( 'user', 'deleted', $user->user_login, Activity::WARNING );
		}
	}

	/**
	 * A user's role changed.
	 *
	 * @param int      $user_id   User id.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Previous roles.
	 * @return void
	 */
	public function on_role_change( $user_id, $role, $old_roles ) {
		$user = get_userdata( $user_id );
		// Fires during user creation too; that case is logged by on_user_created().
		if ( ! $user || ! $old_roles || ( 1 === count( (array) $old_roles ) && in_array( $role, (array) $old_roles, true ) ) ) {
			return;
		}
		$to_admin = 'administrator' === $role;
		Activity::record(
			'user',
			'role',
			$user->user_login,
			$to_admin ? Activity::CRITICAL : Activity::WARNING,
			[ 'detail' => implode( ', ', (array) $old_roles ) . ' → ' . $role ]
		);
		if ( $to_admin ) {
			$this->alert_new_admin( $user );
		}
	}

	/**
	 * A profile was saved: note password and email changes.
	 *
	 * @param int      $user_id  User id.
	 * @param \WP_User $old_user User before the update.
	 * @return void
	 */
	public function on_profile_update( $user_id, $old_user ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! $old_user instanceof \WP_User ) {
			return;
		}
		if ( $user->user_pass !== $old_user->user_pass ) {
			Activity::record( 'user', 'password', $user->user_login, Activity::INFO );
		}
		if ( $user->user_email !== $old_user->user_email ) {
			Activity::record( 'user', 'email', $user->user_login, Activity::WARNING );
		}
	}

	/**
	 * A password was reset through the lost-password flow.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	public function on_password_reset( $user ) {
		if ( $user instanceof \WP_User ) {
			Activity::record( 'user', 'password', $user->user_login, Activity::INFO, [ 'user' => $user->ID ] );
		}
	}

	/**
	 * A plugin was activated.
	 *
	 * @param string $plugin Plugin file.
	 * @return void
	 */
	public function on_plugin_activated( $plugin ) {
		Activity::record( 'plugin', 'activated', $this->plugin_label( $plugin ), Activity::WARNING );
	}

	/**
	 * A plugin was deactivated.
	 *
	 * @param string $plugin Plugin file.
	 * @return void
	 */
	public function on_plugin_deactivated( $plugin ) {
		Activity::record( 'plugin', 'deactivated', $this->plugin_label( $plugin ), Activity::WARNING );
	}

	/**
	 * A plugin was deleted.
	 *
	 * @param string $plugin  Plugin file.
	 * @param bool   $deleted Whether the delete worked.
	 * @return void
	 */
	public function on_plugin_deleted( $plugin, $deleted ) {
		if ( $deleted ) {
			Activity::record( 'plugin', 'deleted', $this->plugin_label( $plugin ), Activity::WARNING );
		}
	}

	/**
	 * A theme was deleted.
	 *
	 * @param string $stylesheet Theme directory name.
	 * @param bool   $deleted    Whether the delete worked.
	 * @return void
	 */
	public function on_theme_deleted( $stylesheet, $deleted ) {
		if ( $deleted ) {
			Activity::record( 'theme', 'deleted', $stylesheet, Activity::WARNING );
		}
	}

	/**
	 * The active theme changed.
	 *
	 * @param string $name New theme name.
	 * @return void
	 */
	public function on_theme_switched( $name ) {
		Activity::record( 'theme', 'switched', (string) $name, Activity::WARNING );
	}

	/**
	 * Plugins or themes were installed or updated.
	 *
	 * @param object $upgrader Upgrader instance.
	 * @param array  $data     What was upgraded.
	 * @return void
	 */
	public function on_upgrade( $upgrader, $data ) {
		if ( empty( $data['type'] ) || ! in_array( $data['type'], [ 'plugin', 'theme' ], true ) || empty( $data['action'] ) ) {
			return;
		}
		$action = 'install' === $data['action'] ? 'installed' : 'updated';
		$items  = [];
		if ( 'plugin' === $data['type'] ) {
			$items = isset( $data['plugins'] ) ? (array) $data['plugins'] : [];
			if ( ! $items && is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) ) {
				$items = array_filter( [ $upgrader->plugin_info() ] );
			}
			$items = array_map( [ $this, 'plugin_label' ], $items );
		} else {
			$items = isset( $data['themes'] ) ? (array) $data['themes'] : [];
			if ( ! $items && is_object( $upgrader ) && method_exists( $upgrader, 'theme_info' ) && $upgrader->theme_info() ) {
				$items = [ $upgrader->theme_info()->get_stylesheet() ];
			}
		}
		foreach ( array_slice( $items, 0, 20 ) as $item ) {
			Activity::record( $data['type'], $action, (string) $item, Activity::INFO );
		}
	}

	/**
	 * WordPress itself was updated.
	 *
	 * @param string $version New version.
	 * @return void
	 */
	public function on_core_updated( $version ) {
		Activity::record( 'core', 'updated', (string) $version, Activity::INFO );
	}

	/**
	 * A watched site option changed.
	 *
	 * @param mixed  $old    Old value.
	 * @param mixed  $value  New value.
	 * @param string $option Option name.
	 * @return void
	 */
	public function on_option_change( $old, $value, $option ) {
		if ( ! is_scalar( $old ) || ! is_scalar( $value ) ) {
			return;
		}
		Activity::record( 'option', 'changed', $option, Activity::CRITICAL, [ 'detail' => $old . ' → ' . $value ] );
	}

	/**
	 * Readable name for a plugin file.
	 *
	 * @param string $plugin Plugin file relative to the plugins directory.
	 * @return string
	 */
	private function plugin_label( $plugin ) {
		$dir = dirname( (string) $plugin );
		return '.' === $dir ? basename( (string) $plugin, '.php' ) : $dir;
	}

	/**
	 * Email the owner that an account now has administrator rights.
	 *
	 * @param \WP_User $user The account.
	 * @return void
	 */
	private function alert_new_admin( $user ) {
		if ( ! Settings::get( 'alert_new_admin' ) ) {
			return;
		}
		$actor = wp_get_current_user();
		Alerts::send(
			__( 'A new administrator account', 'nhrrob-secure' ),
			[
				/* translators: 1: username, 2: email address. */
				sprintf( __( 'The account %1$s (%2$s) now has administrator rights on your site.', 'nhrrob-secure' ), $user->user_login, $user->user_email ),
				$actor->exists()
					/* translators: %s: username. */
					? sprintf( __( 'Changed by: %s', 'nhrrob-secure' ), $actor->user_login )
					: __( 'Nobody was signed in when this happened. If you did not expect it, remove the account and change your passwords.', 'nhrrob-secure' ),
			]
		);
	}
}
