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

namespace Bitpay\Util;

/**
 * @package Bitcore
 */
class Secp256k1Test extends \PHPUnit_Framework_TestCase
{

    public function testA()
    {
        $secp = new Secp256k1();
        //$aHex = '0000000000000000000000000000000000000000000000000000000000000000';
        $aHex = '0';
        $this->assertSame($aHex, $secp::A);
        $this->assertSame('0x'.$aHex, $secp->aHex());
    }

    public function testB()
    {
        $secp = new Secp256k1();
        //$bHex = '0000000000000000000000000000000000000000000000000000000000000007';
        $bHex = '7';
        $this->assertSame($bHex, $secp::B);
        $this->assertSame('0x'.$bHex, $secp->bHex());
    }

    public function testG()
    {
        $secp  = new Secp256k1();
        $gHex  = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
        $gxHex = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
        $gyHex = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
        $this->assertSame($gHex, $secp::G);
        $this->assertSame('0x'.$gHex, $secp->gHex());
        $this->assertSame('0x'.$gxHex, $secp->gxHex());
        $this->assertSame('0x'.$gyHex, $secp->gyHex());
    }

    public function testH()
    {
        $secp = new Secp256k1();
        //$hHex = '01';
        $hHex = '1';
        $this->assertSame($hHex, $secp::H);
        $this->assertSame('0x'.$hHex, $secp->hHex());
    }

    public function testN()
    {
        $secp = new Secp256k1();
        $nHex = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
        $this->assertSame($nHex, $secp::N);
        $this->assertSame('0x'.$nHex, $secp->nHex());
    }

    public function testP()
    {
        $secp = new Secp256k1();
        $pHex = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
        $this->assertSame($pHex, $secp::P);
        $this->assertSame('0x'.$pHex, $secp->pHex());
    }
}
