# -*- coding: utf-8 -*-
"""Submission controller module

@author: moschlar
"""
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

import logging
from time import time
from datetime import datetime

from collections import namedtuple

from itertools import groupby

# turbogears imports
from tg import expose, request, redirect, url, flash, abort, validate,\
    tmpl_context as c, response, TGController

# third party imports
#from tg.i18n import ugettext as _
from repoze.what.predicates import not_anonymous, Any, has_permission
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from sqlalchemy.exc import SQLAlchemyError
from chardet import detect
from tw2.pygmentize import Pygmentize

# project specific imports
from sauce.lib.base import BaseController, post
from sauce.lib.menu import menu
from sauce.lib.authz import is_teacher, has_teacher, has_student, has_user, in_team
from sauce.lib.runner import Runner
from sauce.model import DBSession, Assignment, Submission, Language, Testrun, Event, Judgement
from sauce.widgets import SubmissionForm, JudgementForm, SubmissionTable, SubmissionTableFiller
from tg.util import Bunch

log = logging.getLogger(__name__)

results = namedtuple('results', ('result', 'ok', 'fail', 'total'))


class SubmissionController(TGController):

    allow_only = not_anonymous()

    def __init__(self, submission):

        self.submission = submission
        self.assignment = submission.assignment
        self.event = self.assignment.event

        predicates = []
        for l in submission.lessons:
            predicates.append(has_teacher(l))
        self.allow_only = Any(has_user(submission),
                              in_team(submission),
                              has_teacher(submission.assignment.sheet.event),
                              has_permission('manage'),
                              msg=u'You are not allowed to view this submission',
                              *predicates
                              )

    def _before(self, *args, **kwargs):
        '''Prepare tmpl_context with navigation menus'''
        c.sub_menu = menu(self.submission)
        if request.user:
            c.newer = self.submission.newer_submissions()
            if c.newer:
                log.debug('Newer submissions than %d: ' % (self.submission.id)
                    + ','.join(str(s.id) for s in c.newer))
        else:
            c.newer = []

    @expose()
    def index(self, *args, **kwargs):
        redirect(url(self.submission.url + '/show'))

    @expose('sauce.templates.submission_show')
    def show(self, *args, **kwargs):
        c.pygmentize = Pygmentize(
            formatter_args=dict(
                linenos='table',
                lineanchors='line',
                linespans='line',
            )
        )
        return dict(page=['submissions', 'show'], bread=self.assignment,
                    event=self.event, submission=self.submission)

    def _edit_permissions(self):
        '''Check current users permissions for editing and generate appropriate warnings'''
        if (request.user in self.event.teachers or
                request.user in self.event.tutors or
                'manage' in request.permissions):
            if self.submission.user == request.user:
                # Teacher on Teachers own submission
                if not self.assignment.is_active:
                    flash('The assignment is not active, you should not edit this submission anymore.', 'warning')
            else:
                # Teacher on Students Submission
                flash('You are a teacher trying to edit a student\'s submission. '
                      'You probably want to go to the judgement page instead!', 'warning')
        else:
            if self.submission.user != request.user:
                abort(403)
            # Student on own Submission
            if not self.assignment.is_active:
                flash('This assignment is not active, you can not edit this submission anymore.', 'warning')
                redirect(url(self.submission.url + '/show'))
            elif self.submission.judgement:
                flash('This submission has already been judged, you should not edit it anymore.', 'warning')

    @expose('sauce.templates.submission_edit')
    def edit(self, *args, **kwargs):
        self._edit_permissions()

        c.form = SubmissionForm(action=url('./edit_'))

        return dict(page=['submissions', 'edit'], event=self.event,
            assignment=self.assignment, submission=self.submission)

    @expose()
    @post
    @validate(SubmissionForm, error_handler=edit)
    def edit_(self, language=None, source=None, filename=None, *args, **kwargs):
        self._edit_permissions()

        log.info(dict(submission_id=self.submission.id,
            assignment_id=self.assignment.id,
            language=language, filename=filename, source=source))
        #self.submission.assignment = self.assignment
        #if request.student:
        #    self.submission.student = request.student
        if self.submission.language != language:
            self.submission.language = language
        if self.submission.source != source:
            self.submission.source = source
        if self.submission.filename != filename:
            self.submission.filename = filename
        if self.submission in DBSession.dirty:
            self.submission.modified = datetime.now()
            DBSession.add(self.submission)
        try:
            DBSession.flush()
        except SQLAlchemyError:
            DBSession.rollback()
            log.warn('Submission %d could not be saved', self.submission.id, exc_info=True)
            flash('Your submission could not be saved!', 'error')
            redirect(self.submission.url + '/edit')
        else:
            redirect(self.submission.url + '/result')

    def _judge_permissions(self):
        '''Check current users permissions for judging and generate appropriate warnings'''
        if not request.allowance(self.submission):
            abort(403)

        if self.assignment.is_active:
            flash('The assignment is still active, this submission could still be edited by the student.', 'warning')

    @expose('sauce.templates.submission_judge')
    def judge(self, *args, **kwargs):
        self._judge_permissions()

        c.judgement_form = JudgementForm(action=url('./judge_'))
        c.pygmentize = Pygmentize(
            formatter_args=dict(
                linenos='table',
                lineanchors='line',
                linespans='line',
            )
        )

        options = Bunch(submission_id=self.submission.id,
            submission=self.submission,
            assignment_id=self.assignment.id,
            assignment=self.assignment)

        if self.submission.judgement:
            if self.submission.judgement.annotations:
                options['annotations'] = [dict(line=i, comment=ann)
                    for i, ann in sorted(self.submission.judgement.annotations.iteritems(), key=lambda x: x[0])]
            else:
                options['annotations'] = []
            options['comment'] = self.submission.judgement.comment
            options['corrected_source'] = self.submission.judgement.corrected_source
            options['grade'] = self.submission.judgement.grade

        return dict(page=['submissions', 'judge'], submission=self.submission, options=options)

    @expose()
    @post
    @validate(JudgementForm, error_handler=judge)
    def judge_(self, grade=None, comment=None, corrected_source=None, annotations=None, *args, **kwargs):
        self._judge_permissions()

        judgement_annotations = dict()
        if annotations:
            keyfunc = lambda d: d['line']
            for k, g in groupby(sorted(annotations, key=keyfunc), key=keyfunc):
                judgement_annotations[k] = ', '.join((d['comment'] for d in g))

        judgement_attrs = dict(
            grade=grade, comment=comment, corrected_source=corrected_source,
            annotations=judgement_annotations or None,
        )

        if any((True for x in judgement_attrs.itervalues() if x is not None)):
            # Judgement is not empty
            judgement = self.submission.judgement or Judgement(submission=self.submission)
            judgement.tutor = request.user
            judgement.date = datetime.now()
            for k in judgement_attrs:
                setattr(judgement, k, judgement_attrs[k])
        else:
            # Judgement is empty
            judgement = None

        self.submission.judgement = judgement

        try:
            DBSession.flush()
        except SQLAlchemyError:
            DBSession.rollback()
            log.warn('Submission %d, judgement could not be saved:', self.submission.id, exc_info=True)
            flash('Error saving judgement', 'error')

        redirect(self.submission.url + '/judge')

    @expose()
    def clone(self, *args, **kwargs):
        s = Submission(
            user=request.user,
            assignment=self.submission.assignment,
            filename=self.submission.filename,
            source=self.submission.source,
            language=self.submission.language,
        )

        DBSession.add(s)

        try:
            DBSession.flush()
        except SQLAlchemyError:
            DBSession.rollback()
            flash('Error cloning submission', 'error')
            redirect(url(self.submission.url + '/show'))
        finally:
            s = DBSession.merge(s)
            flash('Cloned submission %d from %d' % (s.id, self.submission.id), 'ok')
            redirect(url(s.url + '/show'))

    @expose()
    def delete(self, *args, **kwargs):
        subm_id = self.submission.id
        subm_url = self.submission.url
        try:
            if (getattr(request, 'user', None) == self.submission.user or
                    request.allowance(self.submission)):
                DBSession.delete(self.submission)
                DBSession.flush()
            else:
                #abort(403)
                flash('You have no permission to delete this Submission', 'warning')
                redirect(url(self.submission.url + '/show'))
        except SQLAlchemyError:
            DBSession.rollback()
            log.warn('Submission %d could not be deleted', self.submission.id, exc_info=True)
            flash('Submission could not be deleted', 'error')
            redirect(url(self.submission.url + '/show'))
        else:
            flash('Submission %d deleted' % (subm_id), 'ok')
            if request.referer and not subm_url in request.referer:
                # Most likely coming from the submission overview page
                redirect(request.referer)
            else:
                redirect(url(self.assignment.url))

    @expose('sauce.templates.submission_result')
    def result(self, force_test=False, *args, **kwargs):
        compilation = None

        # Prepare for laziness!
        # If force_test is set or no tests have been run so far
        if (force_test or not self.submission.testruns or
            # or if any testrun is outdated
            [testrun for testrun in self.submission.testruns
                if testrun.date < self.submission.modified]):
            # re-run tests
            (compilation, testruns, result) = self.submission.run_tests()

        testruns = sorted(set(self.submission.testruns), key=lambda s: s.date)
        result = self.submission.result

        return dict(page=['submissions', 'result'], submission=self.submission,
            compilation=compilation, testruns=testruns, result=result)

    @expose(content_type='text/plain; charset=utf-8')
    def download(self, what=None, *args, **kwargs):
        '''Download source code'''
        response.headerlist.append(('Content-Disposition',
            'attachment;filename=%s' % unicode(self.submission.filename).encode('utf-8')))
        if what and what.startswith('j'):
            if self.submission.judgement and self.submission.judgement.corrected_source:
                return unicode(self.submission.judgement.corrected_source).encode('utf-8')
            else:
                flash('No judgement with corrected source code to download')
                redirect(url(self.submission.url + '/show'))
        else:
            return unicode(self.submission.source).encode('utf-8')

    @expose()
    def source(self, what=None, style='default', linenos=True, *args, **kwargs):
        '''Show (highlighted) source code alone on full page'''
        linenos = linenos in (True, 1, '1', 'True', 'true', 't', 'Yes', 'yes', 'y')

        if what and what.startswith('j'):
            if self.submission.judgement and self.submission.judgement.corrected_source:
                src = self.submission.judgement.corrected_source
            else:
                flash('No judgement with corrected source code to highlight', 'info')
                redirect(url(self.submission.url + '/show'))
        else:
            src = self.submission.source

        pyg = Pygmentize(
            formatter_args=dict(
                full=True,
                title='Submission %d' % (self.submission.id),
                linenos=linenos and 'table' or False,
                lineanchors='line',
                linespans='line',
            )
        )

        return pyg.display(lexer_name=self.submission.language.lexer_name,
                           source=src)


class SubmissionsController(TGController):

    allow_only = not_anonymous(msg=u'Only logged in users may see submissions')

    def __init__(self):
        pass

    def _before(self, *args, **kwargs):
        '''Prepare tmpl_context with navigation menus'''
        pass

    @expose('sauce.templates.submissions')
    def index(self, page=1, *args, **kwargs):
        '''Submission listing page'''

        #TODO: Ugly and stolen from controllers.user

        c.table = SubmissionTable(DBSession)

        teammates = set()
        for team in request.user.teams:
            teammates |= set(team.students)
        teammates.discard(request.user)

        values = SubmissionTableFiller(DBSession).get_value(user_id=request.user.id)

        for teammate in teammates:
            values.extend(SubmissionTableFiller(DBSession).get_value(user_id=teammate.id))

        return dict(page='submissions', view=None, user=request.user, values=values)

    @expose()
    def _lookup(self, submission_id, *args):
        '''Return SubmissionController for specified submission_id'''

        try:
            submission_id = int(submission_id)
            submission = Submission.query.filter_by(id=submission_id).one()
        except ValueError:
            flash('Invalid Submission id: %s' % submission_id, 'error')
            abort(400)
        except NoResultFound:
            flash('Submission %d not found' % submission_id, 'error')
            abort(404)
        except MultipleResultsFound:
            log.error('Database inconsistency: Submission %d' % submission_id, exc_info=True)
            flash('An error occurred while accessing Submission %d' % submission_id, 'error')
            abort(500)

        controller = SubmissionController(submission)
        return controller, args
