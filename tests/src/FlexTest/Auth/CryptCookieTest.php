<?php
namespace FlexTest\Auth;

use Flex\Auth\CryptCookie;
use Flex\Crypt\KeyGenerator\OpenSSLGenerator;

/**
 * Class CryptCookieTest
 *
 * @author Jeff Tunessen <jeff.tunessen@gmail.com>
 */
class CryptCookieTest extends \PHPUnit_Framework_TestCase
{

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
    public function setUp()
    {
        $this->secret = new OpenSSLGenerator();
        $this->secret = $this->secret->generate(64);

        $this->cookie = new CryptCookie('foo', $this->secret);
    }

    /**
     * @return void
     */
    public function tearDown()
    {
        $this->cookie = null;
    }

    /**
     * @test
     */
    public function testGetName()
    {
        $this->assertEquals('foo', $this->cookie->getName());
    }

    /**
     * @test
     */
    public function testGetSecret()
    {
        $this->assertEquals($this->secret, $this->cookie->getSecret());
    }

    /**
     * @test
     */
    public function testData()
    {
        $this->cookie->bar = 'baz';
        $this->assertEquals('baz', $this->cookie->bar);
        $this->assertNull($this->cookie->barbaz);

        $expected = array('bar' => 'baz');
        $this->assertEquals($expected, $this->cookie->getData());

        $expected = array('bar' => '2015');
        $this->cookie->setData($expected);
        $this->assertEquals($expected, $this->cookie->getData());
    }

    /**
     * @test
     * @expectedException \Exception
     * @expectedExceptionMessage missing encryption
     */
    public function testInvalidCookieEncryption()
    {
        new CryptCookie('foo', 'bar', 'baz');
    }

    /**
     * @test
     */
    public function testEncryption()
    {
        $secret = new OpenSSLGenerator();
        $secret = $secret->generate(64);

        $expected = array('foo' => 'bar');

        $cookie = new CryptCookie('foo', $secret);
        $cookie->setData($expected);

        $cookie->encryptData();
        $cookie->decryptData();

        $this->assertEquals($expected, $cookie->getData());

        $cookie->setEncrypted('foo');
        $this->assertEquals('foo', $cookie->getEncrypted());
    }

    /**
     * @test
     */
    public function testReadFromMissingCookie()
    {
        $secret = new OpenSSLGenerator();
        $secret = $secret->generate(64);

        $cookie = new CryptCookie('foo', $secret);
        $result = $cookie->read();

        $this->assertFalse($result);
    }

    /**
     * @test
     */
    public function testReadPreviousRead()
    {
        $secret = new OpenSSLGenerator();
        $secret = $secret->generate(64);

        $expected = array('foo' => 'bar');

        $cookie = new CryptCookie('foo', $secret);
        $cookie->setData($expected);

        $cookie->encryptData();
        $cookie->setData(array());
        $result = $cookie->read();
        $this->assertTrue($result);
        $this->assertEquals($expected, $cookie->getData());

        $cookie->setEncrypted('foo');
        $result = $cookie->read();
        $this->assertFalse($result);
        $this->assertEquals(array(), $cookie->getData());
    }

    /**
     * @test
     * @runInSeparateProcess
     */
    public function testCookie()
    {
        $secret = new OpenSSLGenerator();
        $secret = $secret->generate(64);

        $expected = array('foo' => 'bar');

        $cookie = new CryptCookie('foo', $secret);
        $cookie->setData($expected);

        $cookie->write();
        $cookie->clear();

        $cookie->decryptData();
        $this->assertEquals($expected, $cookie->getData());
    }
}
