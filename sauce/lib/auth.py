# -*- coding: utf-8 -*-
'''
Created on 18.03.2012

@author: moschlar
'''

import logging

#TODO: Use environ instead of request if possible
from tg import request

from repoze.what.predicates import Predicate

log = logging.getLogger(__name__)

class has_student(Predicate):
    '''Check user access for given object type and id'''
    
    message = u'The user must be a student for this %(name)s'
    
    def __init__(self, obj, *args, **kwargs):
        self.obj = obj
        self.name = self.obj.__class__.__name__
        try:
            self.student = self.obj.student
        except:
            self.student = None
        super(has_student, self).__init__(**kwargs)
    
    def evaluate(self, environ, credentials):
        if request.student and request.student == self.student:
            return
        self.unmet()

class has_user(Predicate):
    
    message = u'The user must be attributed for this %(name)s'
    
    def __init__(self, obj, *args, **kwargs):
        self.obj = obj
        self.name = self.obj.__class__.__name__
        try:
            self.user = self.obj.user
        except:
            self.user = None
        super(has_user, self).__init__(**kwargs)
    
    def evaluate(self, environ, credentials):
        if request.user and request.user == self.user:
            return
        self.unmet()

class in_team(Predicate):
    
    message = u'The user must be in a team for this %(name)s'
    
    def __init__(self, obj, *args, **kwargs):
        self.obj = obj
        self.name = self.obj.__class__.__name__
        try:
            self.teams = self.obj.teams
        except:
            self.teams = []
        super(in_team, self).__init__(*args, **kwargs)
    
    def evaluate(self, environ, credentials):
        try:
            if set(request.user.teams) & set(self.teams):
                return
        except:
            self.unmet()

class has_teacher(Predicate):
    
    message = u'The user must be the teacher for this %(name)s'
    
    def __init__(self, obj, *args, **kwargs):
        self.obj = obj
        self.name = self.obj.__class__.__name__
        try:
            self.teacher = self.obj.teacher
        except:
            self.teacher = None
        super(has_teacher, self).__init__(**kwargs)
    
    def evaluate(self, environ, credentials):
        if request.teacher and request.teacher == self.teacher:
            return
        self.unmet()

class has_teachers(Predicate):
    
    message = u'The user must be a teacher for this %(name)s'
    
    def __init__(self, obj, *args, **kwargs):
        self.obj = obj
        self.name = self.obj.__class__.__name__
        self.id = id
        try:
            self.teachers = self.obj.teachers
        except:
            self.teachers = []
        try:
            self.teacher = self.obj.teacher
            self.teachers.append(self.teacher)
        except:
            self.teacher = None
        super(has_teachers, self).__init__(**kwargs)
    
    def evaluate(self, environ, credentials):
        if request.teacher and request.teacher in self.teachers:
            return
        self.unmet()

class is_public(Predicate):
    '''Check if given object is public'''
    
    message = u'This %(name)s must be public'
    
    def __init__(self, obj, *args, **kwargs):
        self.obj = obj
        self.name = self.obj.__class__.__name__
        super(is_public, self).__init__(**kwargs)
    
    def evaluate(self, environ, credentials):
        if hasattr(self.obj, 'public') and not self.obj.public:
            self.unmet()
        return

class is_teacher(Predicate):
    
    message = u'The user must be a teacher'
    
    def evaluate(self, environ, credentials):
        if request.teacher:
            return
        self.unmet()
