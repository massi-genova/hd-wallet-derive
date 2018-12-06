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
use App\Utils\CashAddress;




$address = '1BPcdk3AAjSRDakF6f8dmAZKqEP44Yi3v7';

$bcashaddress = CashAddress::old2new($address);

var_dump($bcashaddress);

$address = '1JzGqsRgSC1tMpFXEfYhyibrVgnt6Sd8TW';

$bcashaddress = CashAddress::old2new($address);

var_dump($bcashaddress);

$address = '1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu';

$bcashaddress = CashAddress::old2new($address);

var_dump($bcashaddress);