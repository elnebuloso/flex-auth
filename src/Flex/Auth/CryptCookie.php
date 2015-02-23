<?php
namespace Flex\Auth;

use Exception;
use Flex\Crypt\CryptInteface;
use Flex\Crypt\Rijandel256Crypt;

/**
 * Class CryptCookie
 *
 * @author Jeff Tunessen <jeff.tunessen@gmail.com>
 */
class CryptCookie {

    /**
     * @var array
     */
    private $data;

    /**
     * @var string
     */
    private $encrypted;

    /**
     * @var CryptInteface
     */
    private $crypt;

    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $secret;

    /**
     * @param string $name
     * @param string $secret
     * @param string $crypt
     * @throws Exception
     */
    public function __construct($name, $secret, $crypt = 'Rijandel256Crypt') {
        $this->read = false;
        $this->data = array();
        $this->name = $name;
        $this->secret = $secret;

        switch($crypt) {
            case 'Rijandel256Crypt':
                $this->crypt = new Rijandel256Crypt($this->secret);
                break;
        }

        if(is_null($this->crypt)) {
            throw new Exception('missing encryption');
        }
    }

    /**
     * @param string $encrypted
     */
    public function setEncrypted($encrypted) {
        $this->encrypted = $encrypted;
    }

    /**
     * @return string
     */
    public function getEncrypted() {
        return $this->encrypted;
    }

    /**
     * @param array $data
     */
    public function setData(array $data) {
        $this->data = $data;
    }

    /**
     * @return array
     */
    public function getData() {
        return $this->data;
    }

    /**
     * @param string $property
     * @param mixed $value
     */
    public function __set($property, $value) {
        $this->data[$property] = $value;
    }

    /**
     * @param string $property
     * @return mixed
     */
    public function __get($property) {
        if(!array_key_exists($property, $this->data)) {
            return null;
        }

        return $this->data[$property];
    }

    /**
     * @return string
     */
    public function getName() {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getSecret() {
        return $this->secret;
    }

    /**
     * @return string
     */
    public function encryptData() {
        $this->encrypted = $this->crypt->encrypt(serialize($this->data));
    }

    /**
     * @return array
     */
    public function decryptData() {
        $this->data = unserialize($this->crypt->decrypt($this->encrypted));
    }

    /**
     * @return bool
     */
    public function read() {
        if(is_null($this->encrypted)) {
            $this->encrypted = @$_COOKIE[$this->name];
        }

        try {
            $this->decryptData();
        }
        catch(Exception $e) {
            $this->data = array();

            return false;
        }

        return true;
    }

    /**
     * @param string $lifetime strtotime valid string
     * @param string $path
     */
    public function write($lifetime = null, $path = '/') {
        $this->encryptData();

        setcookie($this->name, $this->encrypted, (!empty($lifetime)) ? strtotime($lifetime) : 0, $path);
    }

    /**
     * @param string $path
     */
    public function clear($path = '/') {
        setcookie($this->name, null, strtotime('-1 day'), $path);
    }
}