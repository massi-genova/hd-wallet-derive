<?php

namespace App;

require_once __DIR__  . '/../vendor/autoload.php';

// For HD-Wallet Key Derivation
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use Exception;
use App\Utils\NetworkCoinFactory;
use App\Utils\CashAddress;

// For Bip39 Mnemonics
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;

// For ethereum addresses
use kornrunner\Keccak;
use BitWasp\Bitcoin\Crypto\EcAdapter\Key\PublicKeyInterface;
use BitWasp\Bitcoin\Crypto\EcAdapter\Impl\PhpEcc\Serializer\Key\PublicKeySerializer;
use BitWasp\Bitcoin\Crypto\EcAdapter\EcAdapterFactory;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\EccFactory;


/* A class that implements HD wallet key/address derivation
 */
class WalletDerive
{

    // Contains options we care about.
    protected $params;
    protected $hkf;
    
    public function __construct($params)
    {
        $this->params = $params;
        $this->hkf = new HierarchicalKeyFactory();
    }


    /**
     * @return mixed
     */
    private function getParams()
    {
        return $this->params;
    }

    /* Derives child keys/addresses for a given key.
     */
    public function deriveKeys($key)
    {

        $params = $this->getParams();

        $coin        = $params['coin'];
        $regtest     = $params['regtest'];
        $start       = $params['startindex'];
        $end         = $params['startindex'] + $params['numderive'];
        $pathParam   = $params['path'];

        if($regtest)
        {
            $coin = 'btcregtest';
        }

        // prepare the network
        $networkCoinFactory = new NetworkCoinFactory();
        $networkCoin = $networkCoinFactory->getNetworkCoinInstance($coin);
        Bitcoin::setNetwork($networkCoin);
        $network = Bitcoin::getNetwork();


        $master = $this->hkf->fromExtended($key, $network);



        $bcashaddress = '';

        $addrs = array();


        $basePath = is_numeric( $pathParam{0} ) ?  'm/' . $pathParam : $pathParam;
        for($i = $start; $i < $end; $i++)
        {

            $path = $basePath . "/$i";
            $key = $master->derivePath($path);
            

            if(method_exists($key, 'getPublicKey'))
            {

                // bip32 path
                if($coin == 'eth')
                {
                    $address = $this->getEthereumAddress($key->getPublicKey());
                }
                else
                {
                    $ptpkha = new PayToPubKeyHashAddress($key->getPublicKey()->getPubKeyHash());
                    $address = $ptpkha->getAddress();
                }



                if($coin == 'bcc')
                {
                    $bcashaddress = CashAddress::old2new($address);
                }

                $xprv = $key->isPrivate() ? $key->toExtendedKey($network) : null;
                $priv_wif = $key->isPrivate() ? $key->getPrivateKey()->toWif($network) : null;
                $pubkey = $key->getPublicKey()->getHex();
                $pubkeyhash = $key->getPublicKey()->getPubKeyHash()->getHex();
                $xpub = $key->toExtendedPublicKey($network);


            }
            else {
                throw new Exception("multisig keys not supported");
            }



            if($coin == 'bcc')
            {
                $addrs[] = array( 'xprv' => $xprv,
                    'privkey' => $priv_wif,
                    'pubkey' => $pubkey,
                    'pubkeyhash' => $pubkeyhash,
                    'xpub' => $xpub,
                    'address' => $address,
                    'bitcoincash' => $bcashaddress,
                    'index' => $i,
                    'path' => $path);

            }
            else
            {
                $addrs[] = array( 'xprv' => $xprv,
                      'privkey' => $priv_wif,
                      'pubkey' => $pubkey,
                      'pubkeyhash' => $pubkeyhash,
                      'xpub' => $xpub,
                      'address' => $address,
                      'bitcoincash' => '',
                      'index' => $i,
                      'path' => $path);
            }
        }

        return $addrs;
    }

    // converts a bip39 mnemonic string with optional password to an xprv key (string).
    public function mnemonicToKey($mnemonic, $password = null)
    {
//        $bip39 = MnemonicFactory::bip39();
        $seedGenerator = new Bip39SeedGenerator();

        // Derive a seed from mnemonic/password
        $seed = $seedGenerator->getSeed($mnemonic, $password);
        
        // not logging seed.  just in case somebody keeps logs in insecure location.
        // mylogger()->log( "Seed: " . $seed->getHex(), mylogger::info );
        // echo $seed->getHex() . "\n";
        
        $bip32 = $this->hkf->fromEntropy($seed);
        return $bip32->toExtendedKey();
    }

    private function getEthereumAddress(PublicKeyInterface $publicKey)
    {
        static $pubkey_serializer = null;
        static $point_serializer = null;
        if(!$pubkey_serializer){
            $adapter = EcAdapterFactory::getPhpEcc(Bitcoin::getMath(), Bitcoin::getGenerator());
            $pubkey_serializer = new PublicKeySerializer($adapter);
            $point_serializer = new UncompressedPointSerializer(EccFactory::getAdapter());
        }
        $pubKey = $pubkey_serializer->parse($publicKey->getBuffer());
        $point = $pubKey->getPoint();
        $upk = $point_serializer->serialize($point);
        $upk = hex2bin(substr($upk, 2));
        $keccak = Keccak::hash($upk, 256);
        $eth_address_lower = strtolower(substr($keccak, -40));
        $hash = Keccak::hash($eth_address_lower, 256);
        $eth_address = '';
        for($i = 0; $i < 40; $i++) {
            // the nth letter should be uppercase if the nth digit of casemap is 1
            $char = substr($eth_address_lower, $i, 1);
            if(ctype_digit($char))
                $eth_address .= $char;
            else if('0' <= $hash[$i] && $hash[$i] <= '7')
                $eth_address .= strtolower($char);
            else
                $eth_address .= strtoupper($char);
        }
        return '0x'. $eth_address;
    }

    /* Returns all columns available for reports
     */
    static public function all_cols()
    {
        return ['path', 'address', 'bitcoincash', 'xprv', 'xpub', 'privkey', 'pubkey', 'pubkeyhash', 'index'];
    }

    /* Returns default reporting columns
     */
    static public function default_cols()
    {
        return ['path', 'address', 'privkey'];
    }
}

// examples

//php hd-wallet-derive.php --coin=ltc -g --key=Ltpv79cjoATqwsPtgnVFa4AV3nrgCiCoPenqndoVYfyY1EmZuuMnD1DCEAbQE5NEpEBVbKXm786sygYFrR2WVnvfuG1znwDU9yDNvvNxn3nT9tx --numderive=5 --all-cols
//php hd-wallet-derive.php --coin=zec -g --key=xprv9zm6dDUb931Japtf1gMz4bw3CUBoAKULHzW3fRBs7zdmsDfVBZiSDDMYjzQqj3VvBPftNo54JCGoLwMo3nJeGHVDininxzffzpSVBnz2C95 --numderive=5
//php hd-wallet-derive.php --coin=bcc -g --key=xprv9zcYpBfhcJzPwekgCraUG2KtgKKyQJeCXbHzwV9YjhtzEp1cSZzB9thR3S2ys6MzXuC2oBnW33VdauA1cCMm6pUZc8zHjQVzxCh1Ugt2H8p --numderive=5
//php hd-wallet-derive.php --key=xprvA1L51gQKdcH9LiV7HBN8MqHLoaNtQqPmhjJy6pLEJUDRRePGcdUpHVqfB2CgdWZUGjviNDA7EAsKmhJRXGQkbX4usEHRV4zhMhAFthJpAEQ --coin=dash --format=json --cols=all --loglevel=fatalerror --numderive=5 --startindex=0 -g
//php hd-wallet-derive.php --coin=eth -g --key=xprv9zk2L8MQnYwCZc71tr9BC9Ydd93A1bLuNXETuftQ9UMwLPa3fL4NLqgWkRyZLMRK7KurgTghG92kEeNAwojRdmt4CJ2sqEt6V8wovPjoKCr --numderive=5 --all-cols