# -*- coding: utf-8 -*-
'''The Runner library

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

import os, logging
from tempfile import mkdtemp
from subprocess import Popen, PIPE
from threading import Thread
from shutil import rmtree
from collections import namedtuple
from random import randint
from time import time

from shlex import split as _split
# Hope to get around with this in older Python 2 versions
split = lambda a: [b.decode('utf-8') for b in _split(a.encode('utf-8'))]

#from sauce.lib.runner.compiler import compile
#from sauce.lib.runner.interpreter import interpret

log = logging.getLogger(__name__)

process = namedtuple('process', ['returncode', 'stdout', 'stderr'])
compileresult = namedtuple('compileresult', ['result', 'runtime', 'stdout', 'stderr'])
testresult = namedtuple('testresult', ['result', 'partial', 'test', 'runtime', 'output_test', 'output_data', 'error_data', 'returncode'])

# Timeout value for join between sending SIGTERM and SIGKILL to process
THREADKILLTIMEOUT = 0.5


class CompileFirstException(Exception): pass


class TimeoutProcess(object):
    '''Runs an external command until timeout is reached
    
    Assumes that Popen uses PIPE for stdin, stdout and stderr
    Data for stdin may be supplied on instantiation, stdout and
    stderr will be returned from the call.'''
    
    def __init__(self):
        self.argv = None
        self.timeout = None
        self.stdin = None
        self.stdout = ''
        self.stderr = ''
        self.p = None
        self.t = None
    
    def __call__(self, argv, timeout, stdin=None, **kwargs):
        '''Run external command argv until timeout is reached
        
        If stdin is not none the data will be supplied to the
        processes stdin.
        Remaining kwargs will be passed to Popen.
        stderr and stdout are always strings, returncode is -1 
        if timeout occured'''
        
        self.argv = argv
        self.timeout = timeout
        self.stdin = stdin
        
        def target():
            self.p = Popen(self.argv, stdin=PIPE, stdout=PIPE, stderr=PIPE, **kwargs)
            (self.stdout, self.stderr) = self.p.communicate(self.stdin)
        
        self.t = Thread(target=target)
        self.t.start()
        self.t.join(self.timeout)
        
        if self.t.isAlive():
            log.debug("Terminating process %d in thread %s" % (self.p.pid, self.t.name))
            self.p.terminate()
            self.t.join(THREADKILLTIMEOUT)
            if self.t.isAlive():
                log.debug("Killing process %d in thread %s" % (self.p.pid, self.t.name))
                self.p.kill()
            self.stderr += 'Timeout occured'
            self.p.returncode = -1
        
        return process(self.p.returncode, self.stdout, self.stderr)


SUEXEC = '/home/moschlar/workspace/SAUCE/sauce/bin/suexec'
USER = '1001'
GROUP = '1001'


class SuexecTimeoutProcess(TimeoutProcess):

    def __call__(self, argv, *args, **kwargs):
        suexec_argv = [SUEXEC, USER, GROUP]
        suexec_argv.extend(argv)
        return super(SuexecTimeoutProcess, self).__call__(suexec_argv, *args, **kwargs)


def compile(compiler, dir, srcfile, binfile):
    '''Compiles a source file
    
    @param compiler: Compiler object
    @param dir: Working directory
    @param srcfile: Filename of source file
    @param binfile: Filename of object file
    
    @return: (returncode, stdoutdata, stderrdata)
    '''
    
    tp = TimeoutProcess()
    
    # Get compiler information
    log.debug('Compiler: %s' % compiler)
    
    # Assemble compiler command line
    #log.debug('%s' % compiler.argv)
    a = compiler.argv.replace('{srcfile}', os.path.join(dir, srcfile))
    a = a.replace('{binfile}', os.path.join(dir, binfile))
    #log.debug('%s' % a)
    
    args = [compiler.path]
    args.extend(split(a))
    
    log.debug('Command line: %s' % args)
    
    # Run compiler
    (returncode, stdoutdata, stderrdata) = tp(args, timeout=compiler.timeout, 
                                              cwd=dir, shell=False,
                                              # This overrides all other locale environment variables
                                              #env={'LC_ALL': 'de_DE.UTF-8'},
                                              )
    
    try:
        stdoutdata = unicode(stdoutdata, encoding='utf-8')
    except UnicodeDecodeError:
        log.info('Encoding errors in compilation', exc_info=True)
        stdoutdata = unicode(stdoutdata, encoding='utf-8', errors='ignore')
    
    try:
        stderrdata = unicode(stderrdata, encoding='utf-8')
    except UnicodeDecodeError:
        log.info('Encoding errors in compilation', exc_info=True)
        stderrdata = unicode(stderrdata, encoding='utf-8', errors='ignore')
    
    log.debug('Process returned: %d' % returncode)
    log.debug('Process stdout: %s' % stdoutdata.strip())
    log.debug('Process stderr: %s' % stderrdata.strip())
    
    return process(returncode, stdoutdata, stderrdata)


def execute(interpreter, timeout, dir, basename, binfile, stdin=None, argv=''):
    '''Execute or interpret a binfile
    
    @param interpreter: Interpreter object or none
    @param dir: Working directory
    @param binfile: Filename of executable or script file
    @param timeout: Timeout value for test run
    @param stdin: Standard input data
    @param argv: Additional argv to command line
    
    @return: (returncode, stdoutdata, stderrdata)
    '''
    
    tp = TimeoutProcess()
    
    if interpreter:
        # Get interpreter information
        log.debug('Interpreter: %s' % interpreter)
        args = [interpreter.path]
        a = interpreter.argv.replace('{binfile}', binfile)
        a = a.replace('{basename}', basename)
        a = a.replace('{path}', dir)
        args.extend(split(a))
    else:
        args = [os.path.join(dir, binfile)]
    
    if argv:
        args.extend(split(argv))
    
    log.debug('Command line: %s' % args)
    
    # normalize newlines
    #log.debug('stdin: %s' % stdin)
    if stdin:
        stdin = stdin.strip()
        #stdin = stdin.replace('\r\n', '\n').replace('\r', '\n').replace('\n\n','\n')
        stdin = '\n'.join(stdin.splitlines())
    #log.debug('stdin: %s' % stdin)
    
    # Run
    (returncode, stdoutdata, stderrdata) = tp(args, timeout=timeout, 
                                              stdin=stdin, cwd=dir, shell=False,
                                              # This overrides all other locale environment variables
                                              #env={'LC_ALL': 'de_DE.UTF-8'},
                                              )
    
    try:
        stdoutdata = unicode(stdoutdata, encoding='utf-8')
    except UnicodeDecodeError:
        log.info('Encoding errors in execution', exc_info=True)
        stdoutdata = unicode(stdoutdata, encoding='utf-8', errors='ignore')
    
    try:
        stderrdata = unicode(stderrdata, encoding='utf-8')
    except UnicodeDecodeError:
        log.info('Encoding errors in execution', exc_info=True)
        stderrdata = unicode(stderrdata, encoding='utf-8', errors='ignore')
    
    log.debug('Process returned: %d' % returncode)
    log.debug('Process stdout: %s' % stdoutdata.strip())
    log.debug('Process stderr: %s' % stderrdata.strip())
    
    return process(returncode, stdoutdata, stderrdata)

class Runner():
    '''Context Manager-aware Runner class
    
    Use as:
        with Runner(submission) as runner:
            runner.compile()
            ...
            for test in runner.test():
                ...
    
    Temporary directories shall be removed on exit or
    object destruction
    
    Reminder:
    The execution order of magic methods for 
    
        with Test() as t:
            print "..."
    
    is (regardless of any exception):
    
        __init__
        __enter__
        ...
        __exit__
        __del__
    '''
    
    def __init__(self, submission):
        '''Initialize Runner object for given submission
        
        Creates temporary directory and saves source file
        '''
        
        self.submission = submission
        self.assignment = submission.assignment
        self.language = submission.language
        
        # Create temporary directory
        self.tempdir = mkdtemp()
        log.debug('tempdir: %s' % self.tempdir)
        
        # Create temporary source file
        if submission.filename:
            self.basename = os.path.splitext(submission.filename)[0]
        else:
            try:
                self.basename = 'a%d_s%d' % (self.assignment.id, self.submission.id)
            except:
                self.basename = 'test_%d' % (randint(0, 65536))
        
        # Possible overwrite extension of user-supplied filename is intended
        if self.language.extension_src:
            self.srcfile = self.basename + '.' + self.language.extension_src
        else:
            self.srcfile = self.basename
        
        if self.language.extension_bin:
            self.binfile = self.basename + '.' + self.language.extension_bin
        else:
            self.binfile = self.basename
        
        log.debug('srcfile: %s' % self.srcfile)
        
        # Write source code to source file
        with open(os.path.join(self.tempdir, self.srcfile), 'w') as srcfd:
            srcfd.write(submission.source.encode('utf-8'))
    
    def __enter__(self):
        '''Context Manager entry function'''
        
        return self
    
    def __exit__(self, exception_type, exception_value, traceback):
        '''Context Manager exit function'''
        
        if self.tempdir:
            try:
                rmtree(self.tempdir)
            except:
                pass
            finally:
                self.tempdir = None
    
    def __del__(self):
        '''Destructor function
        
        If not already deleted by __exit__ (e.g. if Runner()
        was not used as Context Manager, removes temporary directory
        '''
        
        if self.tempdir:
            try:
                rmtree(self.tempdir)
            except:
                pass
            finally:
                self.tempdir = None
    
    def compile(self):
        '''Compile submission source files, if needed
        
        If submission.language doesn't specify a compiler
        to use, None is returned
        '''
        
        if self.language.compiler:
            start = time()
            (returncode, stdoutdata, stderrdata) = compile(self.language.compiler, self.tempdir, self.srcfile, self.binfile)
            end = time()
            self.compilation = compileresult(returncode == 0, end - start, stdoutdata, stderrdata)
        else:
            self.compilation = None
        return self.compilation
    
    def test(self, visible=True, invisible=False):
        '''Run all associated test cases
        
        Keeps going, even if one test fails.
        '''
        
        if not self.compilation or self.compilation.result:
            tests = []
            if visible:
                tests += self.assignment.visible_tests
            if invisible:
                tests += self.assignment.invisible_tests
            
            for test in tests:
                
                # Write test file, if needed
                if test.input_type == 'file':
                    with open(os.path.join(self.tempdir, test.input_filename or 'indata'), 'w') as infd:
                        infd.write(test.input_data.encode('utf-8'))
                    input = None
                else:
                    input = test.input_data
                
                # Create output file for convenience
                if test.output_type == 'file':
                    with open(os.path.join(self.tempdir, test.output_filename or 'outdata'), 'w') as outfd:
                        pass
                
                # Parse argv, if needed
                if test.argv:
                    a = test.argv.replace('{infile}', os.path.join(self.tempdir, test.input_filename or 'indata'))
                    a = a.replace('{outfile}', os.path.join(self.tempdir, test.output_filename or 'outdata'))
                    a = a.replace('{path}', self.tempdir)
                else:
                    a = ''
                
                start = time()
                process = execute(self.language.interpreter, test.timeout, 
                                  self.tempdir, self.basename, self.binfile, input, a)
                end = time()
                runtime = end - start
                
                if test.output_type == 'file':
                    with open(os.path.join(self.tempdir, test.output_filename or 'outdata'), 'r') as outfd:
                        output = outfd.read()
                        try:
                            output = unicode(output, encoding='utf-8')
                        except UnicodeDecodeError:
                            log.info('Encoding errors in test %d for submission %d' % (test.id, self.submission.id), exc_info=True)
                            output = unicode(output, encoding='utf-8', errors='ignore')
                else:
                    output = process.stdout
                
                (result, partial, output_test, output_data, error) = test.validate(output)
                
                if result or not test.ignore_returncode and process.returncode != 0:
                    yield testresult(result, partial, test, runtime,
                                     output_test, output_data,
                                     process.stderr + error, process.returncode)
                else:
                    yield testresult(False, partial, test, runtime,
                                     output_test, output_data,
                                     process.stderr + error, process.returncode)
        else:
            log.info('Compilation failed, can\'t run tests for Submission %d', self.submission.id)

