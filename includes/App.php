<?php

namespace NHRRob\Secure;

/**
 * App base class
 */
class App {
    /**
     * Render a template
     *
     * @param string $name
     * @param array $args
     */
    public function render( $name, $args = [] ) {
        extract( $args );
        $template = NHRROB_SECURE_PATH . '/templates/' . $name . '.php';

        if ( file_exists( $template ) ) {
            include $template;
        }
    }
}
