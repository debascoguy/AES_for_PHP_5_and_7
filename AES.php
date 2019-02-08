<?php

/**
 * Created by Ademola Aina.
 * Date: 3/11/2018
 *
 * A simple Improved Code Developed Based on original publication at -
 * https://aesencryption.net/
 *
 * Advance Encryption Scheme Algorithm Implementation
 *
 * IMPORTANT!!!
 * We Introduced a key normalization function to enable this implementation to supports both PHP 5.x and 7.x
 */
class AES
{

    const M_CBC = 'cbc';
    const M_CFB = 'cfb';
    const M_ECB = 'ecb';
    const M_NOFB = 'nofb';
    const M_OFB = 'ofb';
    const M_STREAM = 'stream';

    const BLOCK_128 = 128;
    const BLOCK_192 = 192;
    const BLOCK_256 = 256;

    protected $key;         //use either 16, 24 or 32 byte keys for self-128, 192 and 256 respectively
    protected $cipher;
    protected $data;
    protected $mode;
    protected $IV;

    public $cipherKeyRelationship = array(
        MCRYPT_RIJNDAEL_128 => 16,
        MCRYPT_RIJNDAEL_192 => 24,
        MCRYPT_RIJNDAEL_256 => 32
    );
    
    protected static $instance = null;
    
    protected $iv = null;
    
    /**
     * @param string $data
     * @param string $key
     * @param number $blockSize
     * @param string $mode
     */
    public static function getInstance($data = null, $key = null, $blockSize = 256, $mode = 'cbc') {
        if (null === self::$instance){
            self::$instance = new self($data, $key, $blockSize, $mode);
        }
        
        $method = $blockSize . '-' . $mode;
        $instanceMethod = self::$instance->cipher.'-'.self::$instance->mode;
        if (self::$instance->data != $data || self::$instance->key != $key || $method != $instanceMethod) {
            self::$instance->setData($data);
            self::$instance->setKey($key);
            $this->setBlockSize($blockSize);
            $this->setMode($mode);
            if ($method != $instanceMethod){
                $this->setIV("");
            }
        }
        return self::$instance;
    }

    /**
     * @constructor.
     * @param null $data
     * @param null $key
     * @param int $blockSize
     * @param string $mode ( M_ECB: works best if the encrypted value will be going over a URL. )
     */
    private function __construct($data = null, $key = null, $blockSize = 256, $mode = 'cbc')
    {
        $this->setData($data);
        $this->setKey($key);
        $this->setBlockSize($blockSize);
        $this->setMode($mode);
        $this->setIV("");
    }

    /**
     *
     * @param string $data
     */
    public function setData($data)
    {
        $this->data = $data;
    }

    /**
     * @param string $key
     */
    public function setKey($key)
    {
        //Use the ap_system_salt by default but you can use any other key (as needed).
        global $ap_system_salt;
        $this->key = ($key==null) ? $ap_system_salt : $key;
    }

    /**
     * @param $key
     * @param $expectedKeySize
     * @return string
     */
    public static function normalizeKey($key, $expectedKeySize)
    {
        $c = strlen($key);
        if ($c > $expectedKeySize) {
            return substr($key, 0, $expectedKeySize);
        }
        while ($c < $expectedKeySize) {
            $key .= "\0";
            $c++;
        }
        return $key;
    }

    /**
     * @param $blockSize
     */
    public function setBlockSize($blockSize)
    {
        switch ($blockSize) {
            case self::BLOCK_128:
                $this->cipher = MCRYPT_RIJNDAEL_128;
                break;

            case self::BLOCK_192:
                $this->cipher = MCRYPT_RIJNDAEL_192;
                break;

            case self::BLOCK_256:
                $this->cipher = MCRYPT_RIJNDAEL_256;
                break;

            default:  $this->cipher = MCRYPT_RIJNDAEL_256;
                break;
        }
    }

    /**
     * @param $mode
     */
    public function setMode($mode)
    {
        switch ($mode) {
            case self::M_CBC:
                $this->mode = MCRYPT_MODE_CBC;
                break;
            case self::M_CFB:
                $this->mode = MCRYPT_MODE_CFB;
                break;
            case self::M_ECB:
                $this->mode = MCRYPT_MODE_ECB;
                break;
            case self::M_NOFB:
                $this->mode = MCRYPT_MODE_NOFB;
                break;
            case self::M_OFB:
                $this->mode = MCRYPT_MODE_OFB;
                break;
            case self::M_STREAM:
                $this->mode = MCRYPT_MODE_STREAM;
                break;
            default:
                $this->mode = MCRYPT_MODE_ECB;
                break;
        }
    }

    /**
     * @return boolean
     */
    public function validateParams()
    {
        $expectedKeySize = $this->cipherKeyRelationship[$this->cipher];
        if (!empty($this->key)){
            $this->setKey(self::normalizeKey($this->key, $expectedKeySize));
        }
        return ($this->data != null && $this->key != null && $this->cipher != null) ? true: false;
    }

    /**
     * @param $IV
     */
    public function setIV($IV)
    {
        $this->IV = $IV;
    }

    /**
     * @return string
     */
    protected function getIV()
    {
        if (empty($this->IV)) {
            $this->IV = mcrypt_create_iv(mcrypt_get_iv_size($this->cipher, $this->mode), MCRYPT_RAND);
        }
        return $this->IV;
    }

    /**
     * @return string
     * @throws Exception
     */
    public function encrypt()
    {
        if ($this->validateParams()) {
            return trim(
                        base64_encode(
                            rtrim(
                                mcrypt_encrypt(
                                    $this->cipher,
                                    $this->key,
                                    $this->data,
                                    $this->mode,
                                    $this->getIV()), "\0") /** strip off null byte padding */
                        )
            );
        } else {
            throw new \Exception('Invalid params!');
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    public function decrypt()
    {
        if ($this->validateParams()) {
            return trim(
                        rtrim(
                            mcrypt_decrypt(
                                $this->cipher,
                                $this->key,
                                base64_decode($this->data),
                                $this->mode,
                                $this->getIV()), "\0")  /** strip off null byte padding */
            );
        } else {
            throw new \Exception('Invalid params!');
        }
    }

    /**
     * @return array of constants defined in this class.
     */
    static function getConstants() {
        $oClass = new \ReflectionClass(__CLASS__);
        return $oClass->getConstants();
    }

}
