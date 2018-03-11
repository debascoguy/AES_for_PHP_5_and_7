<?php

/**
 * Created by Ademola Aina.
 * Date: 3/11/2018
 *
 * PHP AES encryption with openssl example.(versions 7.x)
 *
 * A simple Improved Code Developed Based on original publication at -
 * https://aesencryption.net/
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

    /**
     * @param $data
     * @param $key
     * @param $blockSize
     * @param $mode
     */
    function __construct($data = null, $key = null, $blockSize = null, $mode = 'CBC') {
        $this->setData($data);
        $this->setKey($key);
        $this->setMethod($blockSize, $mode);
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
            throw new Exception('Invalid block size and mode combination!');
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
     * @return string
     * it must be the same when you encrypt and decrypt
     */
    protected function getIV()
    {
//      return '1234567890123456';
//      return mcrypt_create_iv(mcrypt_get_iv_size($this->cipher, $this->mode), MCRYPT_RAND);
        return openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->method));
    }

    /**
     * @return string
     * @throws Exception
     */
    public function encrypt() {
        if ($this->validateParams()) {
            return trim(openssl_encrypt($this->data, $this->method, $this->key, $this->options,$this->getIV()));
        } else {
            throw new Exception('Invalid params!');
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
            throw new Exception('Invalid params!');
        }
    }

}