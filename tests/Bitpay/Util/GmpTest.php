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

use Bitpay\Point;

class GmpTest extends \PHPUnit_Framework_TestCase
{
    public function testDoubleAndAdd()
    {
        $point = Gmp::doubleAndAdd('0', new Point(0, 0));

        $this->assertInstanceOf('Bitpay\PointInterface', $point);
        $this->assertTrue($point->isInfinity());

        $point = Gmp::doubleAndAdd('1', new Point(1, 1));
        $this->assertEquals('1', $point->getX());
        $this->assertEquals('1', $point->getY());
        $this->assertFalse($point->isInfinity());
    }

    public function testDicimal2binary()
    {
        $data = array(
            array('123456789', '111010110111100110100010101'),
            array('0x123456789', '100100011010001010110011110001001'),
        );

        foreach ($data as $datum) {
            $this->assertSame($datum[1], Gmp::decimal2binary($datum[0]));
        }
    }

    public function testPointDouble()
    {
        // point, Expected X, Expected Y
        $data = array(
            //array(
            //    new Point(100, 100),
            //    '',
            //    '',
            //),
            array(
                new Point(1, 1),
                '28948022309329048855892746252171976963317496166410141009864396001977208667916',
                '14474011154664524427946373126085988481658748083205070504932198000988604333958',
            ),
        );

        foreach ($data as $datum) {
            $point = Gmp::gmpPointDouble($datum[0]);
            //var_dump($point);
            $this->assertGreaterThanOrEqual(77, strlen($point->getX()));
            $this->assertGreaterThanOrEqual(77, strlen($point->getY()));
            $this->assertSame($datum[1], $point->getX());
            $this->assertSame($datum[2], $point->gety());
        }
    }

    public function testGmpPointAdd()
    {
        // A, B, Expected X, Expected Y
        $data = array(
            array(
                new Point(1, 1),
                new Point(1, 1),
                '28948022309329048855892746252171976963317496166410141009864396001977208667916',
                '14474011154664524427946373126085988481658748083205070504932198000988604333958',
            ),
        );
        foreach ($data as $datum) {
            $point = Gmp::gmpPointAdd($datum[0], $datum[1]);
            $this->assertGreaterThanOrEqual(77, strlen($point->getX()));
            $this->assertGreaterThanOrEqual(77, strlen($point->getY()));
            $this->assertSame($datum[2], $point->getX());
            $this->assertSame($datum[3], $point->gety());
        }
    }

    public function testGmpBinconv()
    {
        $data = array(
            array('7361746f736869', 'satoshi'),
            array('0x7361746f736869', 'satoshi'),
        );
        foreach ($data as $datum) {
            $this->assertSame($datum[1], Gmp::gmpBinconv($datum[0]));
        }
    }
}
