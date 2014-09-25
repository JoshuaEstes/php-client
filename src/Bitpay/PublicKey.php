<?php
/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 BitPay, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Bitpay;

use Bitpay\Util\Gmp;
use Bitpay\Util\Secp256k1;
use Bitpay\Util\Util;

/**
 * @package Bitcore
 */
class PublicKey extends Key
{
    /**
     * @var SinKey
     */
    protected $sin;

    /**
     * @var PrivateKey
     */
    protected $privateKey;

    /**
     * @var boolean
     */
    protected $generated = false;

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->x;
    }

    /**
     * @param PrivateKey
     */
    public static function createFromPrivateKey(PrivateKey $private)
    {
        $public = new self();
        $public->setPrivateKey($private);

        return $public;
    }

    /**
     * @return KeyInterface
     */
    public function setPrivateKey(PrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;

        return $this;
    }

    /**
     * Generates an uncompressed and compressed EC public key.
     *
     * @param \Bitpay\PrivateKey $privateKey
     *
     * @return Bitpay\PublicKey
     */
    public function generate()
    {
        if ($this->generated) {
            return $this;
        }

        if (is_null($this->privateKey)) {
            throw new \Exception('Please `setPrivateKey` before you generate a public key');
        }

        if (!$this->privateKey->isGenerated()) {
            $this->privateKey->generate();
        }

        if (!$this->privateKey->isValid()) {
            throw new \Exception('Private Key is invalid and cannot be used to generate a public key');
        }

        $R = Gmp::doubleAndAdd(
            '0x'.$this->privateKey->getHex(),
            new Point(
                '0x'.substr(Secp256k1::G, 0, 62),
                '0x'.substr(Secp256k1::G, 62, 62)
            )
        );

        $RxHex = Util::decimal2hexidecimal($R->getX());
        $RyHex = Util::decimal2hexidecimal($R->getY());

        $RxHex = str_pad($RxHex, 64, '0', STR_PAD_LEFT);
        $RyHex = str_pad($RyHex, 64, '0', STR_PAD_LEFT);

        //var_dump(
        //    $RxHex,
        //    $RyHex
        //);

        $this->x   = $RxHex;
        $this->y   = $RyHex;
        $this->hex = sprintf('%s%s', $RxHex, $RyHex);
        $this->dec = Util::decimal2hexidecimal($this->hex);
        $this->generated = true;

        //var_dump($this->isValidPoint());

        return $this;
    }

    /**
     * Checks to see if the public key is not blank and contains
     * valid decimal and hex valules for this->hex & this->dec
     *
     * @return boolean
     */
    public function isValid()
    {
        return ((!empty($this->hex) && !ctype_xdigit($this->hex)) && (!empty($this->dec) && !ctype_digit($this->dec)));
    }

    public function isValidPoint()
    {
        return Gmp::pointTest(new Point($this->x, $this->y));
    }

    /**
     * @return SinKey
     */
    public function getSin()
    {
        if (!$this->isGenerated()) {
            $this->generate();
        }

        if (null === $this->sin) {
            $this->sin = new SinKey();
            $this->sin->setPublicKey($this);
            $this->sin->generate();
        }

        return $this->sin;
    }

    /**
     * @return boolean
     */
    public function isGenerated()
    {
        return $this->generated;
    }
}
