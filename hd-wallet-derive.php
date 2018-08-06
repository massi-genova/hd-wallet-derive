#!/usr/bin/env php
<?php

/**
 * Entry point for hd-wallet-derive.
 *
 * Code in this file is related to interacting with the shell.
 */

// Let's be strict about things.
require_once __DIR__ . '/vendor/autoload.php';
\strictmode\initializer::init();


use App\Utils\MyLogger;
use App\WalletDerive;
use App\Utils\WalletDeriveReport;
use App\Utils\Util;



/**
 * Our main function.  It performs top-level exception handling.
 */
function main()
{
    // why limit ourselves?    ;-)
    ini_set('memory_limit', -1 );

    try
    {
        // CLI Parameters processing
        list( $params, $success ) = Util::processCliParams();
        if( $success != 0 )
        {
            return $success;
        }

        // Creates WalletDerive object
        $walletDerive = new WalletDerive($params);

        // Key derived from mnemonic if mnemonic is choosen
        $key = @$params['key'] ?: $walletDerive->mnemonicToKey($params['mnemonic'], $params['mnemonic-pw']);
        $addrs = $walletDerive->deriveKeys($key);

        // Prints result
        echo "\n";
        WalletDeriveReport::printResults($params, $addrs);
        return 0;
    }
    catch(Exception $e)
    {
        MyLogger::getInstance()->log_exception( $e );
        
        // print validation errors to stderr.
        if( $e->getCode() == 2 ) {
            fprintf( STDERR, $e->getMessage() . "\n\n" );
        }
        return $e->getCode() ?: 1;
    }
}

main();
