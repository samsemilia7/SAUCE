# -*- coding: utf-8 -*-
'''Language model module

Possible variables in argv command line strings are:

    {path}: Absolute path to temporary working directory
    {basename}: Plain file name without path and extension
    {srcfile}: Filename with source extension
    {binfile}: Filename with binary extension

@author: moschlar
'''

from sqlalchemy import Column, ForeignKey
from sqlalchemy.types import Integer, Unicode, Float
from sqlalchemy.orm import relationship

from sauce.model import DeclarativeBase

class Compiler(DeclarativeBase):
    __tablename__ = 'compilers'
    
    id = Column(Integer, primary_key=True)
    
    name = Column(Unicode(255), nullable=False)
    
    path = Column(Unicode(255), nullable=False)
    argv = Column(Unicode(255), nullable=False, default=u'{srcfile}')
    
    timeout = Column(Float)
    
    def __unicode__(self):
        return self.name

class Interpreter(DeclarativeBase):
    __tablename__ = 'interpreters'
    
    id = Column(Integer, primary_key=True)
    
    name = Column(Unicode(255), nullable=False)
    
    path = Column(Unicode(255), nullable=False)
    argv = Column(Unicode(255), nullable=False, default=u'{binfile}')
    
    def __unicode__(self):
        return self.name

class Language(DeclarativeBase):
    __tablename__ = 'languages'
    
    id = Column(Integer, primary_key=True)
    
    name = Column(Unicode(255), nullable=False)
    
    brush = Column(Unicode(16), nullable=True)
    '''Brush style for SyntaxHighlighter'''
    
    extension_src = Column(Unicode(255))
    extension_bin = Column(Unicode(255))
    
    compiler_id = Column(Integer, ForeignKey('compilers.id'))
    compiler = relationship('Compiler', backref="languages")
    
    interpreter_id = Column(Integer, ForeignKey('interpreters.id'))
    interpreter = relationship('Interpreter', backref="languages")
    
    def __unicode__(self):
        return self.name
