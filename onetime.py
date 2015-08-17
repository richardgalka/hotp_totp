'''
OATH HOTP + TOTP Implementation
Based on http://tools.ietf.org/html/rfc4226
'''

import hmac
import hashlib
import array
import time
import unittest

def TOTP(K, digits=6, window=30):
    '''
    TOTP is a time-based variant of HOTP.
    Params:
        K       - The shared secret key
        digits  - (Optional) controls response length
        window  - (Optional) time window in seconds
    Returns:
        OTP code of 'digits' length
    '''
    C = long(time.time() / window)
    return HOTP(K, C, digits=digits)

def HOTP(K, C, digits=6):
    '''
    HOTP is a hmac based OTP alg
    Params:
        K       - The shared secret key
        C       - The counter. Required sych between server and client
        digits  - (Optional) controls response length
    Return:
        OTP code of 'digits' length
    '''
    C_bytes = _long_to_byte_array(C)
    hmac_sha1 = hmac.new(key=K, msg=C_bytes, digestmod=hashlib.sha1).hexdigest()
    return Truncate(hmac_sha1)[-digits:]

def Truncate(hmac_sha1):
    offset = int(hmac_sha1[-1], 16)
    binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)

def _long_to_byte_array(long_num):
    byte_array = array.array('B')
    for i in reversed(range(0, 8)):
        byte_array.insert(0, long_num & 0xff)
        long_num >>= 8
    return byte_array


class HotpTest(unittest.TestCase):
    '''
    Test case based on vectors from http://www.ietf.org/rfc/rfc4226.txt
    '''
    def setUp(self):
        self.key_string = '12345678901234567890'

    def test_hotp_vectors(self):
        result_vector = [755224, 287082, 359152, 969429, 338314, 254676,
                              287922, 162583, 399871, 520489, 060613]
        for i in range(0, 10):
            self.assertEquals(HOTP(self.key_string, i),
                              str(result_vector[i]))

    def test_totp(self):
        ''' we should not change value more then once in several thousand
        test runs (ie: window size)
        '''
        value = TOTP(self.key_string, digits=8, window=20)
        value_changes = 0  # TOTP result change count
        for i in range(0, 100000):
            new_totp = TOTP(self.key_string, digits=8, window=20)
            if new_totp != value:
                value_changes += 1
                value = new_totp
        self.assertTrue(value_changes <= 1)

if __name__ == '__main__':
    unittest.main()
