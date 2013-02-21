'''
Created on 19.12.2013

@author: moschlar
'''
#
## SAUCE - System for AUtomated Code Evaluation
## Copyright (C) 2013 Moritz Schlarb
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License for more details.
##
## You should have received a copy of the GNU Affero General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from unittest import TestCase
from sauce.tests import *

from sauce.lib.runner import SuexecTimeoutProcess

__all__ = ['TestSuexecTimeoutProcess']


class TestSuexecTimeoutProcess(TestCase):
    '''Test the timeout-aware process runner'''
    
    def setUp(self):
        '''Set up TimeoutProcess object'''
        
        self.p = SuexecTimeoutProcess()

    def test_id(self):
        '''Test the id program'''
        
        argv = ['/bin/id']
        timeout = 1
        t = self.p(argv, timeout)
        self.assertEqual(t.returncode, 0)
        self.assertIn('1001', t.stderr)
        self.assertNotIn('1000', t.stderr)


    def test_ok(self):
        '''Test a program that returns quickly'''
        
        argv = ['/bin/date']
        timeout = 1
        t = self.p(argv, timeout)
        # If process finished before timeout, it should return 0
        self.assertEqual(t.returncode, 0, "%s ran into %d second timeout..." % (" ".join(argv), timeout))
    
    def test_fail(self):
        '''Test a program that does not return quickly'''
        
        argv = ['/bin/sleep', '2']
        timeout = 1
        t = self.p(argv, timeout)
        # If process does not finish before timeout, it returns -15
        self.assertNotEqual(t.returncode, 0, "%s did not run into %d second timeout..." % (" ".join(argv), timeout))
