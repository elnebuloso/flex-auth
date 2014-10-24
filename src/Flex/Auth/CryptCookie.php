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
     * @var array
     */
    private $data;

    /**
     * @param string $name
     * @param string $secret
     * @param string $crypt
     */
    public function __construct($name, $secret, $crypt = 'Rijandel256Crypt') {
        $this->data = array();
        $this->name = $name;
        $this->secret = $secret;

        switch($crypt) {
            case 'Rijandel256Crypt':
            default:
                $this->crypt = new Rijandel256Crypt($this->secret);
                break;
        }
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
     * @param array $data
     */
    public function setData($data) {
        $this->data = $data;
    }

    /**
     * @return array
     */
    public function getData() {
        return $this->data;
    }

    /**
     * @return bool|mixed
     */
    public function read() {
        if(!isset($_COOKIE[$this->name])) {
            return false;
        }

        try {
            $data = unserialize($this->crypt->decrypt($_COOKIE[$this->name]));
        }
        catch(Exception $e) {
            return false;
        }

        $this->data = $data;

        return true;
    }

    /**
     * @param string $lifetime strtotime valid string
     * @param string $path
     */
    public function write($lifetime = null, $path = '/') {
        setcookie($this->name, $this->crypt->encrypt(serialize($this->data)), (!empty($lifetime)) ? strtotime($lifetime) : 0, $path);
    }

    /**
     * @param string $path
     */
    public function clear($path = '/') {
        setcookie($this->name, null, strtotime('-1 day'), $path);
    }
}