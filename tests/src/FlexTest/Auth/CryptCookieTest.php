<?php
namespace FlexTest\Auth;

use Flex\Auth\CryptCookie;
use Flex\Crypt\KeyGenerator\OpenSSLGenerator;

/**
 * Class CryptCookieTest
 *
 * @author Jeff Tunessen <jeff.tunessen@gmail.com>
 */
class CryptCookieTest extends \PHPUnit_Framework_TestCase {

    /**
     * @var CryptCookie
     */
    private $cookie;

    /**
     * @var string
     */
    private $secret;

    /**
     * @return void
     */
    public function setUp() {
        $this->secret = new OpenSSLGenerator();
        $this->secret = $this->secret->generate(64);

        $this->cookie = new CryptCookie('foo', $this->secret);
    }

    /**
     * @return void
     */
    public function tearDown() {
        $this->cookie->clear();
        $this->cookie = null;
    }

    /**
     * @test
     * @runInSeparateProcess
     */
    public function test_getName() {
        $this->assertEquals('foo', $this->cookie->getName());
    }

    /**
     * @test
     * @runInSeparateProcess
     */
    public function test_getSecret() {
        $this->assertEquals($this->secret, $this->cookie->getSecret());
    }

    /**
     * @test
     * @runInSeparateProcess
     */
    public function test_data() {
        $this->cookie->bar = 'baz';
        $this->assertEquals('baz', $this->cookie->bar);
        $this->assertNull($this->cookie->barbaz);

        $expected = array('bar' => 'baz');
        $this->assertEquals($expected, $this->cookie->getData());

        $expected = array('bar' => '2015');
        $this->cookie->setData($expected);
        $this->assertEquals($expected, $this->cookie->getData());
    }
}