<?php

namespace NHRRob\Secure;

/**
 * The admin class
 */
class Admin {
    
    /**
     * Initialize the class
     */
    public function __construct() {
        $this->dispatch_actions();
        new Admin\Menu();
    }

    /**
     * Dispatch and bind actions
     *
     * @return void
     */
    public function dispatch_actions() {
        // Future admin actions can be added here
    }
}
