<?php

/**
 * Created by Ademola Aina.
 * Date: 3/11/2018
 *
 * A simple Improved Code Developed Based on original publication at -
 * https://aesencryption.net/
 *
 * Advance Encryption Scheme Algorithm Implementation
 * PHP AES encryption with openssl example.(versions 7.x)
 */
class AES_OPENSSL
{
    /**
     * @var string
     */
    protected $key;

    /**
     * @var string
     */
    protected $data;

    /**
     * @var string
     */
    protected $method;
    

    /**
     * Available OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING
     *
     * @var $options
     */
    protected $options = 0;

    /** @BLOCK_SIZE */
    const BLOCK_128 = 128;
    const BLOCK_192 = 192;
    const BLOCK_256 = 256;

    /** @MODE */
    const M_CBC = 'CBC';
    const M_CBC_HMAC_SHA1 = 'CBC-HMAC-SHA1';
    const M_CBC_HMAC_SHA256 = 'CBC-HMAC-SHA256';
    const M_CFB = 'CFB';
    const M_CFB1 = 'CFB1';
    const M_CFB8 = 'CFB8';
    const M_CTR = 'CTR';
    const M_ECB = 'ECB';
    const M_OFB = 'OFB';
    const M_XTS  = 'XTS';
    
    
    protected static $instance = null;
    
    protected $iv = null;
    
    /**
     * @param string $data
     * @param string $key
     * @param number $blockSize
     * @param string $mode
     */
    public static function getInstance($data = null, $key = null, $blockSize = 256, $mode = 'CBC') {
        if (null === self::$instance){
            self::$instance = new self($data, $key, $blockSize, $mode);
        }
        
        $method = 'AES-' . $blockSize . '-' . $mode;
        if (self::$instance->data != $data || self::$instance->key != $key ||  self::$instance->method != $method ) {
            self::$instance->setData($data);
            self::$instance->setKey($key);
            self::$instance->setMethod($blockSize, $mode);
            if (self::$instance->method != $method){
                //Reset IV for the new method of encryption protocol
                $this->setIv();
            }
        }
        return self::$instance;
    }

    /**
     * @param string $data
     * @param string $key
     * @param number $blockSize
     * @param string $mode
     */
    private function __construct($data = null, $key = null, $blockSize = 256, $mode = 'CBC') {
        $this->setData($data);
        $this->setKey($key);
        $this->setMethod($blockSize, strtoupper($mode));
        $this->setIv($this->method);
    }

    /**
     *
     * @param $data
     */
    public function setData($data) {
        $this->data = $data;
    }

    /**
     *
     * @param $key
     */
    public function setKey($key) {
        $this->key = $key;
    }

    /**
     * @param $blockSize
     * @param string $mode
     * @throws Exception
     *
     * CBC 128 192 256
     * CBC-HMAC-SHA1 128 256
     * CBC-HMAC-SHA256 128 256
     * CFB 128 192 256
     * CFB1 128 192 256
     * CFB8 128 192 256
     * CTR 128 192 256
     * ECB 128 192 256
     * OFB 128 192 256
     * XTS 128 256
     */
    public function setMethod($blockSize, $mode = 'CBC') {
        if($blockSize==self::BLOCK_192 && in_array($mode, array('CBC-HMAC-SHA1','CBC-HMAC-SHA256','XTS'))){
            $this->method=null;
            throw new \Exception('Invalid block size and mode combination!');
        }
        $this->method = 'AES-' . $blockSize . '-' . $mode;
    }
    /**
     *
     * @return boolean
     */
    public function validateParams() {
        return ($this->data != null && $this->method != null );
    }
    
    /**
     * @param unknown $method
     */
    public function setIv($method = "") {
        if (empty($method)){
            $method = $this->method;
        }
        $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
    }

    /**
     * @return string
     * it must be the same when you encrypt and decrypt
     */
    protected function getIV()
    {
        return $this->iv;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function encrypt() {
        if ($this->validateParams()) {
            return trim(openssl_encrypt($this->data, $this->method, $this->key, $this->options,$this->getIV()));
        } else {
            throw new \Exception('Invalid params!');
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    public function decrypt() {
        if ($this->validateParams()) {
            return trim(openssl_decrypt($this->data, $this->method, $this->key, $this->options,$this->getIV()));
        } else {
            throw new \Exception('Invalid params!');
        }
    }

}
